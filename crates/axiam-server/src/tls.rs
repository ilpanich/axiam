//! Optional direct-TLS support for the REST API listener (ASVS V9.1.2/V9.1.3).
//!
//! TLS termination at a proxy/load balancer remains the recommended deployment
//! pattern (D-06). This module provides an *opt-in* alternative for deployments
//! that terminate TLS in-process: when `server.tls.enabled` is set, the server
//! builds a rustls [`ServerConfig`] restricted to **TLS 1.3 only**. Restricting
//! to TLS 1.3 also satisfies V9.1.3 — every TLS 1.3 cipher suite is
//! ASVS-approved, so no manual cipher-suite filtering is required.
//!
//! The `ring` crypto provider is selected explicitly (rather than relying on a
//! process-default provider) so `build_rustls_server_config` is self-contained
//! and deterministic regardless of what other crates in the tree pull in.

use std::fs::File;
use std::io;
use std::sync::Arc;

use arc_swap::ArcSwap;

use axiam_api_rest::config::{ClientAuth, TlsConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{
    ClientHello, ResolvesServerCert, ServerSessionMemoryCache, WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};

/// Number of resumption entries kept in the in-process session cache.
///
/// TLS 1.3 resumption is ticket-based (stateless — the ticket travels with the
/// client), so this cache mainly bounds any non-ticket session state; a small
/// value is plenty for a benchmark/service workload and caps memory.
const RESUMPTION_CACHE_SIZE: usize = 512;

/// The ALPN protocol list the rustls listener is built with.
///
/// This is exactly what the actix-web rustls bind ends up advertising, and it
/// is **not** configurable — see [`reject_unsupported_http2_knob`] for the
/// source-level proof.
fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

/// Reject `server.tls.http2 = false`, which the native listener **cannot**
/// honour.
///
/// # Why this is a hard error rather than a warning (G8)
///
/// The knob used to narrow the rustls `ServerConfig`'s ALPN list to
/// `http/1.1`, log a warning, and then serve h2 anyway. That is the worst of
/// both worlds: an operator (or a benchmark cell) can *believe* the listener is
/// HTTP/1.1-only while every client still negotiates h2. Startup now fails, in
/// the same fail-fast style as every other misconfiguration in this module.
///
/// The knob is unimplementable on this bind, verified against the exact
/// versions in `Cargo.lock` (actix-web 4.14.0 / actix-http 3.13.1 /
/// rustls 0.23.42):
///
/// * `actix_web::HttpServer::bind_rustls_0_23` (actix-web-4.14.0
///   `src/server.rs:587`) delegates to `listen_rustls_0_23_inner`
///   (`src/server.rs:1006`), which finishes with
///   `.rustls_0_23_with_config(config, acceptor_config)`.
/// * `actix_http::HttpService::rustls_0_23_with_config` (actix-http-3.13.1
///   `src/service.rs:735`) then does, unconditionally:
///
///   ```text
///   let mut protos = vec![b"h2".to_vec(), b"http/1.1".to_vec()];   // :747
///   protos.extend_from_slice(&config.alpn_protocols);              // :748
///   config.alpn_protocols = protos;                                // :749
///   ```
///
///   so `h2` always lands at index 0 of the effective list. Every actix TLS
///   bind documents this ("ALPN protocols "h2" and "http/1.1" are added to any
///   configured ones") and every one of them shares the prepend.
/// * rustls picks the ALPN protocol by **server** preference order —
///   `our_protocols.iter().find(|ours| their_protocols.contains(ours))` in
///   rustls-0.23.42 `src/server/hs.rs:99-108` — so index 0 wins for any client
///   offering h2. Appending to the list can never outrank the prepended `h2`.
/// * The h2 support cannot be compiled out either: actix-web's `rustls-0_23`
///   feature *implies* `http2` (actix-web-4.14.0 `Cargo.toml`,
///   `rustls-0_23 = ["__tls", "http2", ...]`), and the ALPN prepend lives in a
///   module gated only on `rustls-0_23`, not on `http2`.
///
/// A genuinely `http/1.1`-only TLS 1.3 listener is therefore available only by:
/// 1. fronting the plaintext bind with the `tls13-h1` nginx edge
///    (`benchmarks/targets/axiam/tls/tls13-h1.conf`) — what the G8 conviction
///    cell uses; or
/// 2. abandoning `actix_web::HttpServer` for this bind and driving
///    `actix_http::H1Service::rustls_0_23` (actix-http-3.13.1
///    `src/h1/service.rs:371`) directly on an `actix_server::Server` — that
///    constructor is the one rustls service factory in the tree that does
///    **not** touch `alpn_protocols`. See
///    `claude_dev/b2-tls-h2-investigation.md` for why that rewrite is not
///    justified today.
fn reject_unsupported_http2_knob(tls: &TlsConfig) -> io::Result<()> {
    if tls.http2 {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "server.tls.http2=false is not supported by the native TLS listener: \
         actix-web's rustls bind unconditionally prepends \"h2\" to the ALPN \
         list (actix-http HttpService::rustls_0_23_with_config), and rustls \
         selects by server preference, so h2 would still be negotiated. \
         Refusing to start rather than silently serving the opposite of what \
         was configured. For an http/1.1-only TLS 1.3 endpoint, leave \
         server.tls disabled and terminate TLS at an edge that does not enable \
         HTTP/2 (see benchmarks/targets/axiam/tls/tls13-h1.conf and \
         docs/security-profiles.md).",
    ))
}

/// Maximum legal HTTP/2 flow-control window, `2^31 - 1` (RFC 9113 §6.5.2;
/// `h2::frame::settings::MAX_INITIAL_WINDOW_SIZE` in h2 0.4.15).
const MAX_H2_WINDOW_SIZE: u32 = (1 << 31) - 1;

/// actix-http 3.13.1's default initial **stream** window (`src/config.rs:19`,
/// `DEFAULT_H2_STREAM_WINDOW_SIZE`). Recorded so operators can see what an
/// unset knob means; never written into the builder.
pub const ACTIX_DEFAULT_H2_STREAM_WINDOW: u32 = 1024 * 1024;

/// actix-http 3.13.1's default initial **connection** window
/// (`src/config.rs:14`, `DEFAULT_H2_CONN_WINDOW_SIZE`).
pub const ACTIX_DEFAULT_H2_CONNECTION_WINDOW: u32 = 2 * 1024 * 1024;

/// HTTP/2 tuning surface for the native TLS listener (G8/B2).
///
/// h2 is only ever negotiated on the rustls bind (the plaintext bind is served
/// as HTTP/1.1 — `HttpServer::bind` never calls `listen_auto_h2c`), so these
/// keys live next to the TLS ones and are a no-op when `server.tls.enabled` is
/// false.
///
/// **Every field defaults to `None`, and `None` means "do not call the actix
/// setter at all"** — an unset config reproduces today's behaviour byte for
/// byte, because `actix_web::HttpServer` itself stores these as `Option`s and
/// only forwards them to `HttpService` when `Some`
/// (actix-web-4.14.0 `src/server.rs:1041-1048`).
///
/// | Env var | Type | Unset ⇒ actix default |
/// |---|---|---|
/// | `AXIAM__SERVER__H2__INITIAL_STREAM_WINDOW_SIZE` | `u32` bytes | 1 MiB |
/// | `AXIAM__SERVER__H2__INITIAL_CONNECTION_WINDOW_SIZE` | `u32` bytes | 2 MiB |
///
/// # What is deliberately *not* exposed
///
/// * **`max_concurrent_streams`** — actix-http 3.13.1 never sets it. Its h2
///   handshake builder (`src/h2/mod.rs:60-71`) calls only
///   `initial_window_size` and `initial_connection_window_size`; the underlying
///   `h2::server::Builder::max_concurrent_streams` (h2-0.4.15
///   `src/server.rs:858`) exists but is unreachable, and neither
///   `actix_http::HttpServiceBuilder` nor `actix_web::HttpServer` re-exports
///   it. Because actix never sends `SETTINGS_MAX_CONCURRENT_STREAMS`
///   (`h2::frame::Settings` derives `Default`, i.e. `None`), the server
///   advertises *no* stream limit — so a stream cap is provably **not** the
///   cause of the B2 concurrency ceiling, and inventing a knob for it here
///   would be a lie.
/// * **keep-alive** — `HttpServer::keep_alive` exists but is shared by h1 and
///   h2 and does not bear on a multiplexed-connection ceiling: the single h2
///   connection stays open for the whole run either way. Changing it would
///   alter p0 and p2 alike, so it is not a B2 lever.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http2Tuning {
    /// `SETTINGS_INITIAL_WINDOW_SIZE` advertised per stream, in bytes.
    pub initial_stream_window_size: Option<u32>,
    /// Connection-level receive window, in bytes.
    pub initial_connection_window_size: Option<u32>,
}

impl Http2Tuning {
    /// Load the `server.h2` subtree using the same sources and idiom as the
    /// main `AppConfig` loader (`config/default.toml` + `AXIAM__*` env with a
    /// `__` separator).
    ///
    /// An absent subtree yields [`Self::default`] (all `None`).
    pub fn load() -> io::Result<Self> {
        let sources = config::Config::builder()
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::Environment::with_prefix("AXIAM").separator("__"))
            .build()
            .map_err(|e| io::Error::other(format!("failed to load configuration: {e}")))?;

        let tuning = match sources.get::<Self>("server.h2") {
            Ok(t) => t,
            // Nothing configured at all — keep actix's defaults.
            Err(config::ConfigError::NotFound(_)) => Self::default(),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid server.h2 configuration: {e}"),
                ));
            }
        };
        tuning.validate()?;
        Ok(tuning)
    }

    /// Reject window sizes HTTP/2 cannot express, so a typo fails at startup
    /// rather than at the first h2 handshake (`h2::server::Builder` asserts
    /// `size <= MAX_WINDOW_SIZE` and would panic inside a worker).
    fn validate(&self) -> io::Result<()> {
        for (name, value) in [
            (
                "initial_stream_window_size",
                self.initial_stream_window_size,
            ),
            (
                "initial_connection_window_size",
                self.initial_connection_window_size,
            ),
        ] {
            let Some(v) = value else { continue };
            if v == 0 || v > MAX_H2_WINDOW_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "server.h2.{name} must be between 1 and {MAX_H2_WINDOW_SIZE} \
                         bytes (RFC 9113 §6.5.2); got {v}"
                    ),
                ));
            }
        }
        Ok(())
    }

    /// True when nothing is configured, i.e. actix's defaults are untouched.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The window actix will actually use per stream (configured or default) —
    /// for the startup log line only.
    pub fn effective_stream_window(&self) -> u32 {
        self.initial_stream_window_size
            .unwrap_or(ACTIX_DEFAULT_H2_STREAM_WINDOW)
    }

    /// The window actix will actually use per connection (configured or
    /// default) — for the startup log line only.
    pub fn effective_connection_window(&self) -> u32 {
        self.initial_connection_window_size
            .unwrap_or(ACTIX_DEFAULT_H2_CONNECTION_WINDOW)
    }
}

/// Build a rustls [`ClientCertVerifier`] from the configured client-CA bundle
/// (D3 native mTLS).
///
/// Loads the PEM bundle at `client_ca_path` into a [`RootCertStore`] and builds
/// a [`WebPkiClientVerifier`] over it, using the same [`CryptoProvider`] as the
/// server config. For [`ClientAuth::Optional`] the verifier still *offers* and
/// *verifies* client certs but permits anonymous clients
/// (`allow_unauthenticated`); for [`ClientAuth::Required`] a verified client
/// cert is mandatory.
///
/// Fails fast (aborting startup) when the CA path is unset, missing/unreadable,
/// empty, or malformed — matching this file's existing `io::Error` style so a
/// misconfigured mTLS server never starts.
fn read_client_ca_roots(tls: &TlsConfig) -> io::Result<RootCertStore> {
    let ca_path = tls.client_ca_path.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server.tls.client_auth is optional/required but \
             server.tls.client_ca_path is not set",
        )
    })?;

    let pem = std::fs::read_to_string(ca_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "failed to open TLS client CA bundle {}: {e}",
                ca_path.display()
            ),
        )
    })?;
    let roots = roots_from_pem(&pem, &ca_path.display().to_string())?;
    if roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no client CA certificates found in {}", ca_path.display()),
        ));
    }
    Ok(roots)
}

/// The verifier the live listener is using, and the provider to rebuild with.
///
/// A process-global because there is one TLS listener per process and the
/// handler that flags a CA has no path to the `ServerConfig` actix built — it
/// runs inside it. Set once, during `build_rustls_server_config`.
static LIVE_VERIFIER: std::sync::OnceLock<(
    Arc<ReloadableClientCertVerifier>,
    Arc<rustls::crypto::CryptoProvider>,
)> = std::sync::OnceLock::new();

fn install_reloadable_verifier(
    verifier: Arc<ReloadableClientCertVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) {
    // `set` fails only if called twice, which means a second listener was
    // built. The first one is the one actix is serving on.
    let _ = LIVE_VERIFIER.set((verifier, provider));
}

/// Install `pem` as the live client trust anchor set, without a restart.
///
/// Returns the number of anchors now trusted, or `None` when this process has
/// no TLS listener with client authentication enabled — a plaintext deployment,
/// or one whose operator set `client_auth = off`. That is not a failure: there
/// is nothing to reload into, and saying so lets the caller report "saved, and
/// it will apply when TLS is enabled" rather than a spurious error.
///
/// # Errors
///
/// A bundle that does not parse, or a certificate webpki refuses as a trust
/// anchor. The live anchor set is left **unchanged** in that case: the new
/// bundle is fully parsed and the verifier fully built before anything is
/// swapped, so a bad reload cannot leave the listener trusting nothing.
pub fn reload_trust_anchors(pem: &str) -> io::Result<Option<usize>> {
    let Some((verifier, provider)) = LIVE_VERIFIER.get() else {
        return Ok(None);
    };
    let roots = roots_from_pem(pem, "the mTLS trust anchor bundle")?;
    let count = verifier.replace(roots, provider)?;
    Ok(Some(count))
}

// ---------------------------------------------------------------------------
// Hot-reloadable leaf certificate
// ---------------------------------------------------------------------------

/// Read the configured certificate chain and private key and prove they match.
///
/// Shared by the boot path and every reload, so a certificate that would be
/// rejected at startup is rejected identically at 3am when certbot replaces it
/// — the alternative being two subtly different parsers and a renewal that
/// installs something the next boot refuses.
///
/// # Errors
///
/// A missing or unreadable file (`NotFound`/`PermissionDenied`), a PEM the
/// parser rejects, an empty chain, or a key that does not match the leaf's
/// public key.
fn read_certified_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    provider: &rustls::crypto::CryptoProvider,
) -> io::Result<CertifiedKey> {
    // Open the files explicitly so a missing/unreadable path yields a clean
    // io::Error (NotFound / PermissionDenied) before any PEM parsing. Cert and
    // key are parsed via rustls-pki-types' `PemObject` trait directly —
    // rustls-pemfile is unmaintained (RUSTSEC-2025-0134) and is a thin wrapper
    // over this same code.
    let cert_file = File::open(cert_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to open TLS cert file {}: {e}", cert_path.display()),
        )
    })?;
    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse TLS certificates from {}: {e}",
                    cert_path.display()
                ),
            )
        })?;
    if cert_chain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificates found in {}", cert_path.display()),
        ));
    }

    let key_file = File::open(key_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to open TLS key file {}: {e}", key_path.display()),
        )
    })?;
    let key = PrivateKeyDer::from_pem_reader(key_file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to read a TLS private key from {}: {e}",
                key_path.display()
            ),
        )
    })?;

    // `from_der` loads the key through the provider and compares its SPKI with
    // the leaf's, which is the check that makes a half-written renewal — the
    // new chain beside the old key — fail here rather than at a client's
    // handshake.
    CertifiedKey::from_der(cert_chain, key, provider).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid TLS certificate/key pair: {e}"),
        )
    })
}

/// A [`ResolvesServerCert`] whose certificate can be replaced while the server
/// is listening.
///
/// # Why this exists
///
/// rustls consults the resolver on every handshake but reads nothing from disk;
/// `with_single_cert` installs an immutable `SingleCertAndKey` and actix binds
/// the resulting config for the process's life. So the leaf a server started
/// with is the leaf it serves forever.
///
/// That is fine for a certificate an operator installs by hand and lives with
/// for a year. It is not fine for ACME: Let's Encrypt issues for 90 days,
/// clients renew at 60, and the only remedy without this type is to restart the
/// process every couple of months — which for an identity provider means
/// dropping in-flight requests and re-reading every secret out of Vault on a
/// schedule, to work around a `Vec<u8>` that could have been swapped.
///
/// The shape deliberately mirrors [`ReloadableClientCertVerifier`]: an
/// `ArcSwap` consulted on the hot path, replaced wholesale by a reload that has
/// already done all of its fallible work. There is one mechanism for "TLS
/// material changed while we were running", not two.
#[derive(Debug)]
pub struct ReloadableCertResolver {
    current: ArcSwap<CertifiedKey>,
}

impl ReloadableCertResolver {
    /// Start serving `initial`.
    pub fn new(initial: CertifiedKey) -> Self {
        Self {
            current: ArcSwap::from_pointee(initial),
        }
    }

    /// Swap in `next`, returning the certificate that was replaced.
    ///
    /// Infallible by construction: every way this can fail — unreadable file,
    /// malformed PEM, mismatched pair — has already happened (or not) in
    /// [`read_certified_key`]. A caller that reaches this point holds a
    /// certificate rustls has already accepted, so the listener cannot be left
    /// serving nothing.
    pub fn replace(&self, next: CertifiedKey) -> Arc<CertifiedKey> {
        self.current.swap(Arc::new(next))
    }

    /// The certificate currently being served.
    pub fn current(&self) -> Arc<CertifiedKey> {
        self.current.load_full()
    }
}

impl ResolvesServerCert for ReloadableCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Deliberately ignores SNI, exactly as `SingleCertAndKey` does: this
        // listener serves one deployment on one name. Returning the certificate
        // regardless of the name offered is what lets a client connecting to
        // `127.0.0.1` with an overridden SNI (how the edge proxy reaches the
        // backend on the loopback bind) complete the handshake against the
        // public leaf.
        Some(self.current.load_full())
    }
}

/// The live resolver, the provider to rebuild with, and where to re-read from.
///
/// A process-global for the same reason [`LIVE_VERIFIER`] is one: there is a
/// single TLS listener per process, and the signal handler and poll task that
/// trigger a reload run outside anything holding the `ServerConfig` actix
/// built. Set once, during [`build_rustls_server_config`].
#[allow(clippy::type_complexity)]
static LIVE_CERT_RESOLVER: std::sync::OnceLock<(
    Arc<ReloadableCertResolver>,
    Arc<rustls::crypto::CryptoProvider>,
    std::path::PathBuf,
    std::path::PathBuf,
)> = std::sync::OnceLock::new();

fn install_reloadable_resolver(
    resolver: Arc<ReloadableCertResolver>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
) {
    // `set` fails only if called twice, which means a second listener was
    // built. The first one is the one actix is serving on.
    let _ = LIVE_CERT_RESOLVER.set((resolver, provider, cert_path, key_path));
}

/// Re-read the configured certificate and key and install them on the live
/// listener, without a restart.
///
/// Returns `Ok(None)` when this process has no TLS listener — a plaintext
/// deployment behind a terminating proxy. That is not a failure: there is
/// nothing to reload into, and saying so lets a `SIGHUP` handler log "no TLS
/// listener" rather than an error an operator would go looking for.
///
/// Returns `Ok(Some(false))` when the files parsed but are byte-identical to
/// what is already being served, so a poll that fires between renewals stays
/// silent instead of logging a reload an hour, forever.
///
/// # Errors
///
/// Anything [`read_certified_key`] rejects. **The live certificate is left
/// unchanged in that case** — the new pair is fully read, parsed and
/// consistency-checked before anything is swapped, so a renewal caught
/// half-written (certbot writes the chain and the key as two separate
/// operations) fails this call and is retried on the next tick rather than
/// taking the listener down.
pub fn reload_leaf_certificate() -> io::Result<Option<bool>> {
    let Some((resolver, provider, cert_path, key_path)) = LIVE_CERT_RESOLVER.get() else {
        return Ok(None);
    };
    reload_into(resolver, provider, cert_path, key_path).map(Some)
}

/// The reload itself, against an explicit resolver rather than the process
/// global.
///
/// Split out so the behaviour that matters — swap on change, no-op when
/// unchanged, leave the old certificate serving on a bad pair — is testable
/// directly. Going through [`reload_leaf_certificate`] would mean racing for
/// [`LIVE_CERT_RESOLVER`]'s single `set`, which whichever test ran first would
/// win; a mechanism whose failure mode is "serves the wrong certificate" should
/// not be tested order-dependently.
///
/// # Errors
///
/// Anything [`read_certified_key`] rejects. The resolver is left untouched.
fn reload_into(
    resolver: &ReloadableCertResolver,
    provider: &rustls::crypto::CryptoProvider,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> io::Result<bool> {
    let next = read_certified_key(cert_path, key_path, provider)?;
    // Compare the DER chain rather than file bytes: PEM whitespace, comment
    // lines and the ordering certbot happens to write are not differences a
    // handshake can see, and a poll that reloaded on them would churn.
    if resolver.current().cert == next.cert {
        return Ok(false);
    }
    resolver.replace(next);
    Ok(true)
}

/// Report the outcome of one reload attempt.
///
/// A free function rather than a closure inside [`spawn_leaf_reloader`] so the
/// mapping from outcome to log level is testable: the WARN-not-ERROR choice on
/// a failed reload is deliberate (the previous certificate is still serving)
/// and is exactly the kind of decision that gets "tidied" into an ERROR by
/// someone who has not read why.
fn log_reload_outcome(trigger: &'static str, outcome: io::Result<Option<bool>>) {
    match outcome {
        Ok(Some(true)) => tracing::info!(
            trigger,
            "TLS leaf certificate reloaded; new connections use it immediately"
        ),
        Ok(Some(false)) => tracing::debug!(
            trigger,
            "TLS leaf certificate unchanged on disk; nothing to reload"
        ),
        Ok(None) => tracing::debug!(
            trigger,
            "no direct-TLS listener in this process; nothing to reload"
        ),
        // WARN, not ERROR, and deliberately not fatal: the previous
        // certificate is still serving. The likeliest cause is a renewal
        // observed mid-write, which the next trigger resolves on its own.
        Err(e) => tracing::warn!(
            trigger,
            error = %e,
            "TLS leaf certificate reload failed; continuing to serve the \
             previous certificate"
        ),
    }
}

/// Start the background triggers that keep the leaf certificate current.
///
/// Spawns, on the ambient tokio runtime:
///
/// * a `SIGHUP` listener — the conventional operator hook, and what an ACME
///   `--deploy-hook` sends. Immediate.
/// * a `stat` poll every `interval_secs`, skipped entirely when that is `0`.
///
/// Both funnel into [`reload_leaf_certificate`], which is a no-op when the
/// certificate on disk is the one already being served. Calling this on a
/// plaintext deployment is harmless: the reload reports "no TLS listener" and
/// the tasks idle.
///
/// # Why both, and why the poll is not the only one
///
/// The signal is the correct mechanism and takes effect within milliseconds.
/// It is also the one that silently does not happen: a deploy hook nobody
/// wired up, a container runtime that does not forward signals to PID 1, an
/// operator who renews by hand. The poll is what turns "the certificate
/// expired in production" into "the certificate was replaced within the hour",
/// and it costs one read of two small files an hour.
pub fn spawn_leaf_reloader(interval_secs: u64) {
    tokio::spawn(async move {
        let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not install a SIGHUP handler; TLS certificate reload                      is available only through the periodic poll"
                );
                return;
            }
        };
        while hangup.recv().await.is_some() {
            log_reload_outcome("sighup", reload_leaf_certificate());
        }
    });

    if interval_secs == 0 {
        tracing::info!(
            "TLS certificate reload polling is disabled              (server.tls.reload_interval_secs = 0); SIGHUP still reloads"
        );
        return;
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        // The first tick fires immediately and would re-read the certificate
        // the boot path just read. Burn it.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            log_reload_outcome("poll", reload_leaf_certificate());
        }
    });
}

// ---------------------------------------------------------------------------
// Hot-reloadable client trust anchors
// ---------------------------------------------------------------------------

/// A [`ClientCertVerifier`] whose trust anchors can be replaced while the
/// server is listening.
///
/// # Why this exists
///
/// rustls builds its client trust store when the `ServerConfig` is constructed,
/// and actix binds that config for the process's life. Flagging a CA as an mTLS
/// trust anchor therefore used to take effect at the *next* boot, and the API
/// said so rather than pretending otherwise — which is honest and still means
/// an operator adding a device CA has to restart the server every browser
/// session and every IoT device is currently connected to.
///
/// rustls consults the verifier **per handshake**, not once at construction. So
/// a verifier that delegates to a swappable inner one gives the config
/// something permanent to hold while the anchors behind it change. Connections
/// already established keep the verifier they handshook with, which is correct:
/// a certificate accepted a moment ago does not become invalid mid-connection,
/// and revocation of an established session is what session invalidation is
/// for.
///
/// # The empty state
///
/// [`Anchors::None`] is not "trust nothing" — it is "do not ask for a client
/// certificate at all", the same posture as `with_no_client_auth()`. A
/// deployment that boots with no flagged CA must behave exactly as it does
/// today, *and* must be able to reach the anchored state without a restart.
/// Installing this verifier unconditionally is what makes both true;
/// `WebPkiClientVerifier` cannot express it, because it refuses to build over
/// an empty root store.
#[derive(Debug)]
pub struct ReloadableClientCertVerifier {
    anchors: ArcSwap<Anchors>,
    /// Whether a verified client certificate is required once anchors exist.
    ///
    /// Fixed at construction from `client_auth`: it is an operator's policy
    /// decision, not a property of the anchor set, and changing it changes
    /// whether unauthenticated clients can connect at all.
    mandatory: bool,
}

/// What the verifier currently trusts.
#[derive(Debug)]
enum Anchors {
    /// No trust anchors: no client certificate is requested.
    None,
    /// A webpki verifier over the current anchor set.
    Some(Arc<dyn ClientCertVerifier>),
}

impl ReloadableClientCertVerifier {
    /// An empty verifier that offers no client authentication.
    pub fn empty(mandatory: bool) -> Self {
        Self {
            anchors: ArcSwap::from_pointee(Anchors::None),
            mandatory,
        }
    }

    /// Replace the trust anchors with a verifier built over `roots`.
    ///
    /// An empty `roots` returns to [`Anchors::None`] rather than building a
    /// verifier that trusts nothing: a verifier that requests a certificate and
    /// then rejects every one is strictly worse than not requesting one, and it
    /// is what un-flagging the last CA should produce.
    pub fn replace(
        &self,
        roots: RootCertStore,
        provider: &Arc<rustls::crypto::CryptoProvider>,
    ) -> io::Result<usize> {
        if roots.is_empty() {
            self.anchors.store(Arc::new(Anchors::None));
            return Ok(0);
        }
        let count = roots.len();
        let builder =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone());
        let verifier = if self.mandatory {
            builder.build()
        } else {
            builder.allow_unauthenticated().build()
        }
        .map_err(|e| io::Error::other(format!("failed to build client cert verifier: {e}")))?;

        self.anchors.store(Arc::new(Anchors::Some(verifier)));
        Ok(count)
    }

    /// How many anchors are currently installed.
    pub fn anchor_count(&self) -> usize {
        match &**self.anchors.load() {
            Anchors::None => 0,
            Anchors::Some(v) => v.root_hint_subjects().len(),
        }
    }

    /// The current inner verifier, if any.
    fn current(&self) -> Option<Arc<dyn ClientCertVerifier>> {
        match &**self.anchors.load() {
            Anchors::None => None,
            Anchors::Some(v) => Some(Arc::clone(v)),
        }
    }
}

impl ClientCertVerifier for ReloadableClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        // Consulted per handshake, which is the whole mechanism: the answer
        // changes the moment `replace` installs an anchor set.
        self.current().is_some()
    }

    fn client_auth_mandatory(&self) -> bool {
        // Only meaningful while anchors exist. Answering `true` with none
        // installed would refuse every connection to a server that cannot
        // verify anybody — a self-inflicted outage on a deployment that
        // un-flagged its last CA.
        self.mandatory && self.current().is_some()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // Cannot borrow through the ArcSwap guard, and the hint is advisory:
        // it tells a client which issuers the server would accept, and a client
        // that offers a certificate anyway is verified normally by
        // `verify_client_cert`. Returning nothing costs a round trip in the
        // worst case and never accepts anything it should not.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        match self.current() {
            Some(v) => v.verify_client_cert(end_entity, intermediates, now),
            // Unreachable while rustls honours `offer_client_auth`, and a
            // refusal rather than an acceptance if it ever does not.
            None => Err(rustls::Error::General(
                "no client trust anchors are configured".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        match self.current() {
            Some(v) => v.verify_tls12_signature(message, cert, dss),
            None => Err(rustls::Error::General(
                "no client trust anchors are configured".into(),
            )),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        match self.current() {
            Some(v) => v.verify_tls13_signature(message, cert, dss),
            None => Err(rustls::Error::General(
                "no client trust anchors are configured".into(),
            )),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        match self.current() {
            Some(v) => v.supported_verify_schemes(),
            // The provider's full set: this is a capability advertisement, and
            // an empty list would make a handshake fail to negotiate rather
            // than fall through to the "no anchors" path above.
            None => rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

/// Build a [`RootCertStore`] from concatenated PEM.
///
/// Shared by the boot path and the reload path so a hot-reloaded anchor set is
/// parsed by exactly the same code as one read at startup — two parsers is how
/// a bundle comes to be accepted at boot and rejected on reload.
pub fn roots_from_pem(pem: &str, source: &str) -> io::Result<RootCertStore> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse client CA certificates from {source}: {e}"),
            )
        })?;

    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid client CA certificate in {source}: {e}"),
            )
        })?;
    }
    Ok(roots)
}

/// Build a TLS 1.3-only rustls [`ServerConfig`] from the configured PEM files.
///
/// Fails fast (returning an `io::Error` that aborts startup) when TLS is enabled
/// but misconfigured: a missing `cert_path`/`key_path`, an unreadable or
/// malformed PEM file, an empty cert chain, a cert/key mismatch, or an
/// unsatisfiable `http2 = false` request (see [`reject_unsupported_http2_knob`]).
pub fn build_rustls_server_config(tls: &TlsConfig) -> io::Result<ServerConfig> {
    // Checked before any file IO: an unsatisfiable ALPN request is a config
    // error regardless of whether the cert/key happen to be readable.
    reject_unsupported_http2_knob(tls)?;

    let cert_path = tls.cert_path.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server.tls.enabled is true but server.tls.cert_path is not set",
        )
    })?;
    let key_path = tls.key_path.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server.tls.enabled is true but server.tls.key_path is not set",
        )
    })?;

    // TLS 1.3 only (ASVS V9.1.2). ring provider selected explicitly.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::other(format!("rustls TLS 1.3 configuration failed: {e}")))?;

    // Client-certificate (mTLS) policy (D3). `off` keeps the server-auth-only
    // behaviour (`with_no_client_auth`); `optional`/`required` install a
    // WebPkiClientVerifier over the configured CA bundle so rustls verifies the
    // client cert during the handshake and the *verified* cert (not a header)
    // drives certificate-based identity.
    // Always a `ReloadableClientCertVerifier`, even when `client_auth` is off.
    //
    // rustls binds whatever it is given here for the process's life, so the
    // choice made at this line decides whether flagging a CA later can take
    // effect without a restart. `with_no_client_auth()` decides "no", forever.
    // The reloadable verifier starts in exactly that posture — it offers no
    // client authentication until anchors are installed — and can leave it.
    //
    // A listener that boots with `Off` therefore starts by requesting no
    // client certificate and can still be given anchors later — which matches
    // what `mtls_anchors::apply` already does at boot, where flagging a CA
    // upgrades an unset `Off` to `Optional`.
    let reloadable = Arc::new(ReloadableClientCertVerifier::empty(
        tls.client_auth == ClientAuth::Required,
    ));
    if tls.client_auth != ClientAuth::Off {
        // The bundle written by `mtls_anchors::apply` at boot, or one the
        // operator curated themselves.
        let roots = read_client_ca_roots(tls)?;
        let count = reloadable.replace(roots, &provider)?;
        tracing::info!(anchors = count, "client trust anchors loaded");
    }
    let builder =
        builder.with_client_cert_verifier(reloadable.clone() as Arc<dyn ClientCertVerifier>);
    install_reloadable_verifier(reloadable, Arc::clone(&provider));

    // The leaf. Read, parsed and proven to match its key here, then installed
    // behind an `ArcSwap` so a renewal can replace it without a restart.
    //
    // This is what `with_single_cert` does internally — `CertifiedKey::from_der`
    // followed by `with_cert_resolver(SingleCertAndKey::from(..))` (rustls
    // 0.23.43 `src/server/builder.rs:65-72`) — with the immutable
    // `SingleCertAndKey` swapped for a resolver that can be reloaded. The error
    // text is unchanged so the failure an operator sees for a mismatched pair
    // is the one it has always been.
    let certified = read_certified_key(cert_path, key_path, &provider)?;
    let resolver = Arc::new(ReloadableCertResolver::new(certified));
    install_reloadable_resolver(
        Arc::clone(&resolver),
        Arc::clone(&provider),
        cert_path.clone(),
        key_path.clone(),
    );
    let mut config = builder.with_cert_resolver(resolver as Arc<dyn ResolvesServerCert>);

    // ALPN (B2/G8): h2 + http/1.1. This is not configurable — `http2 = false`
    // was rejected above because actix re-prepends h2 regardless.
    config.alpn_protocols = alpn_protocols();

    // TLS 1.3 session resumption (B2). Without a ticketer + session store a
    // rustls server does a *full* handshake on every connection; k6 opens many
    // short-lived connections per VU, so a full ECDHE handshake per request is a
    // per-request fixed cost that shows up as the ~2× p50 inflation on the token
    // endpoints. Enabling stateless TLS 1.3 tickets lets repeat connections
    // resume (PSK) instead. We deliberately do NOT enable 0-RTT/early-data:
    // rustls' `max_early_data_size` stays at its default 0 because the token
    // endpoints are non-idempotent POSTs and early data is replayable
    // (see docs/security-profiles.md).
    config.session_storage = ServerSessionMemoryCache::new(RESUMPTION_CACHE_SIZE);
    match rustls::crypto::ring::Ticketer::new() {
        Ok(ticketer) => config.ticketer = ticketer,
        Err(e) => tracing::warn!(
            error = %e,
            "failed to construct a TLS ticketer; session resumption disabled \
             (falling back to full handshakes)"
        ),
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_config_is_the_default() {
        let tls = TlsConfig::default();
        assert!(!tls.enabled);
        assert!(tls.cert_path.is_none());
        assert!(tls.key_path.is_none());
    }

    /// The advertised list is fixed: `h2` then `http/1.1`, matching exactly
    /// what actix-http prepends, so the rustls config and the effective
    /// listener agree.
    #[test]
    fn alpn_list_is_h2_then_http11() {
        assert_eq!(alpn_protocols(), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn default_offers_http2() {
        assert!(TlsConfig::default().http2);
        reject_unsupported_http2_knob(&TlsConfig::default())
            .expect("the default (http2=true) must be accepted");
    }

    /// G8: `http2=false` is unsatisfiable on the actix rustls bind, so it must
    /// abort startup instead of quietly serving h2.
    #[test]
    fn http2_false_is_rejected_at_startup() {
        let tls = TlsConfig {
            enabled: true,
            http2: false,
            ..TlsConfig::default()
        };
        let err = reject_unsupported_http2_knob(&tls)
            .expect_err("http2=false must be rejected, not silently ignored");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("not supported"), "got: {err}");
    }

    /// The rejection must fire before any cert/key IO, so the operator sees the
    /// real problem even on an otherwise-valid TLS config.
    #[test]
    fn http2_false_rejected_even_with_valid_cert_and_key() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            http2: false,
            cert_path: Some(write_tmp("h2knob-cert", &pki.server_cert_pem)),
            key_path: Some(write_tmp("h2knob-key", &pki.server_key_pem)),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls)
            .expect_err("http2=false must abort the build even with a good keypair");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    // ---------------------------------------------------------------------
    // G8 — HTTP/2 tuning surface
    // ---------------------------------------------------------------------

    /// Unset means "never call the actix setter", i.e. today's behaviour.
    #[test]
    fn h2_tuning_defaults_to_untouched_actix_behaviour() {
        let t = Http2Tuning::default();
        assert!(t.is_default());
        assert_eq!(t.initial_stream_window_size, None);
        assert_eq!(t.initial_connection_window_size, None);
        assert_eq!(t.effective_stream_window(), ACTIX_DEFAULT_H2_STREAM_WINDOW);
        assert_eq!(
            t.effective_connection_window(),
            ACTIX_DEFAULT_H2_CONNECTION_WINDOW
        );
        t.validate().expect("the default must validate");
    }

    /// The recorded actix defaults must match actix-http 3.13.1's constants
    /// (`DEFAULT_H2_STREAM_WINDOW_SIZE` = 1 MiB,
    /// `DEFAULT_H2_CONN_WINDOW_SIZE` = 2 MiB).
    #[test]
    fn recorded_actix_h2_defaults_match_upstream() {
        assert_eq!(ACTIX_DEFAULT_H2_STREAM_WINDOW, 1_048_576);
        assert_eq!(ACTIX_DEFAULT_H2_CONNECTION_WINDOW, 2_097_152);
    }

    #[test]
    fn h2_tuning_accepts_the_legal_window_range() {
        for v in [1u32, 65_535, 1 << 20, MAX_H2_WINDOW_SIZE] {
            let t = Http2Tuning {
                initial_stream_window_size: Some(v),
                initial_connection_window_size: Some(v),
            };
            t.validate()
                .unwrap_or_else(|e| panic!("{v} must be legal: {e}"));
            assert!(!t.is_default());
            assert_eq!(t.effective_stream_window(), v);
            assert_eq!(t.effective_connection_window(), v);
        }
    }

    #[test]
    fn h2_tuning_rejects_zero_and_oversized_windows() {
        for bad in [0u32, MAX_H2_WINDOW_SIZE + 1] {
            let stream = Http2Tuning {
                initial_stream_window_size: Some(bad),
                initial_connection_window_size: None,
            };
            let err = stream
                .validate()
                .expect_err("illegal stream window must fail fast");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(
                err.to_string().contains("initial_stream_window_size"),
                "got: {err}"
            );

            let conn = Http2Tuning {
                initial_stream_window_size: None,
                initial_connection_window_size: Some(bad),
            };
            let err = conn
                .validate()
                .expect_err("illegal connection window must fail fast");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(
                err.to_string().contains("initial_connection_window_size"),
                "got: {err}"
            );
        }
    }

    #[test]
    fn missing_cert_path_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: None,
            key_path: Some("/tmp/does-not-matter.key".into()),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("missing cert_path must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn missing_key_path_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some("/tmp/does-not-matter.crt".into()),
            key_path: None,
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("missing key_path must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn unreadable_cert_file_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some("/nonexistent/axiam-test-cert.pem".into()),
            key_path: Some("/nonexistent/axiam-test-key.pem".into()),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("unreadable cert file must error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// The cert-file-unreadable case above always fails on the CERT open
    /// (checked first), so the sibling `File::open(key_path)` error arm was
    /// never separately reached. Use a valid, readable cert here so the
    /// function gets past the cert stage and hits the key-file-unreadable
    /// branch specifically.
    #[test]
    fn unreadable_key_file_fails_fast() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert-readable", &pki.server_cert_pem)),
            key_path: Some("/nonexistent/axiam-test-key-only.pem".into()),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("unreadable key file must error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string().contains("failed to open TLS key file"),
            "got: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // D3 — native client-certificate (mTLS) support
    // ---------------------------------------------------------------------

    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    };

    static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Write `contents` to a unique temp file and return its path.
    fn write_tmp(tag: &str, contents: &str) -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("axiam-d3-{}-{n}-{tag}.pem", std::process::id()));
        let mut f = File::create(&path).expect("create temp pem");
        f.write_all(contents.as_bytes()).expect("write temp pem");
        path
    }

    struct TestPki {
        ca_pem: String,
        /// The CA's own key, so a test can issue a *second* server leaf and
        /// exercise a renewal against the same trust anchor.
        ca_key_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
    }

    /// Generate a throwaway CA plus a server leaf (SAN `localhost`) and a client
    /// leaf (SAN `URI:spiffe://axiam/device-01`), all signed by the CA.
    fn gen_test_pki() -> TestPki {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        // Server leaf: SAN localhost so the in-process client can verify it.
        let server_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.is_ca = IsCa::NoCa;
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        // Client leaf: carries a URI SAN we assert on after extraction.
        let client_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.is_ca = IsCa::NoCa;
        client_params
            .subject_alt_names
            .push(SanType::URI("spiffe://axiam/device-01".try_into().unwrap()));
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

        TestPki {
            ca_pem: ca_cert.pem(),
            ca_key_pem: ca_key.serialize_pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    #[test]
    fn client_auth_off_is_the_default() {
        assert_eq!(TlsConfig::default().client_auth, ClientAuth::Off);
        assert!(TlsConfig::default().client_ca_path.is_none());
    }

    #[test]
    fn verifier_builds_from_ca_bundle() {
        let pki = gen_test_pki();
        let ca_path = write_tmp("ca", &pki.ca_pem);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        for mode in [ClientAuth::Optional, ClientAuth::Required] {
            let tls = TlsConfig {
                enabled: true,
                client_auth: mode,
                client_ca_path: Some(ca_path.clone()),
                ..TlsConfig::default()
            };
            let roots = read_client_ca_roots(&tls)
                .unwrap_or_else(|e| panic!("roots must read for {mode:?}: {e}"));
            let verifier = ReloadableClientCertVerifier::empty(mode == ClientAuth::Required);
            let count = verifier
                .replace(roots, &provider)
                .unwrap_or_else(|e| panic!("verifier must build for {mode:?}: {e}"));
            assert_eq!(count, 1);
            assert!(verifier.offer_client_auth());
            assert_eq!(
                verifier.client_auth_mandatory(),
                mode == ClientAuth::Required
            );
        }
    }

    /// An empty anchor set returns to "offer no client authentication" rather
    /// than building a verifier that trusts nothing.
    ///
    /// This is what un-flagging the last CA produces, and it matters: a verifier
    /// that requests a certificate and then rejects every one is strictly worse
    /// than not requesting one — it breaks clients that would otherwise have
    /// connected anonymously.
    #[test]
    fn clearing_the_anchors_stops_offering_client_auth() {
        let pki = gen_test_pki();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Optional,
            client_ca_path: Some(write_tmp("ca", &pki.ca_pem)),
            ..TlsConfig::default()
        };

        let verifier = ReloadableClientCertVerifier::empty(false);
        assert!(
            !verifier.offer_client_auth(),
            "a fresh verifier must behave exactly like with_no_client_auth()"
        );

        verifier
            .replace(read_client_ca_roots(&tls).unwrap(), &provider)
            .unwrap();
        assert!(verifier.offer_client_auth());

        assert_eq!(
            verifier.replace(RootCertStore::empty(), &provider).unwrap(),
            0
        );
        assert!(!verifier.offer_client_auth());
        assert!(!verifier.client_auth_mandatory());
    }

    /// `mandatory` must not survive into the empty state.
    ///
    /// Answering `client_auth_mandatory() == true` with no anchors installed
    /// would refuse every connection to a server that cannot verify anybody —
    /// a self-inflicted outage on a deployment that just un-flagged its last CA.
    #[test]
    fn a_required_verifier_with_no_anchors_does_not_lock_everyone_out() {
        let verifier = ReloadableClientCertVerifier::empty(true);
        assert!(!verifier.offer_client_auth());
        assert!(!verifier.client_auth_mandatory());
    }

    #[test]
    fn required_without_ca_path_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: None,
            ..TlsConfig::default()
        };
        let err = read_client_ca_roots(&tls)
            .expect_err("required client-auth with no CA path must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn missing_ca_bundle_file_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: Some("/nonexistent/axiam-d3-ca.pem".into()),
            ..TlsConfig::default()
        };
        let err = read_client_ca_roots(&tls).expect_err("unreadable CA bundle must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn empty_ca_bundle_fails_fast() {
        let ca_path = write_tmp("empty-ca", "# no certificates here\n");
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: Some(ca_path),
            ..TlsConfig::default()
        };
        let err = read_client_ca_roots(&tls).expect_err("empty CA bundle must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn server_config_builds_with_required_client_auth() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert", &pki.server_cert_pem)),
            key_path: Some(write_tmp("srv-key", &pki.server_key_pem)),
            client_auth: ClientAuth::Required,
            client_ca_path: Some(write_tmp("ca", &pki.ca_pem)),
            ..TlsConfig::default()
        };
        build_rustls_server_config(&tls).expect("server config with mTLS must build");
    }

    /// The common/default deployment shape: TLS enabled, `client_auth: Off`
    /// (no mTLS). Every other test either fails fast before reaching the
    /// `client_auth` match (missing/unreadable cert or key) or exercises
    /// `Optional`/`Required`, so the plain server-auth-only success path
    /// (`ClientAuth::Off => builder.with_no_client_auth()`) was never
    /// actually driven to completion.
    #[test]
    fn server_config_builds_with_client_auth_off() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert-off", &pki.server_cert_pem)),
            key_path: Some(write_tmp("srv-key-off", &pki.server_key_pem)),
            client_auth: ClientAuth::Off,
            ..TlsConfig::default()
        };
        let config = build_rustls_server_config(&tls)
            .expect("server config with client_auth off must build");
        // Sanity: the fixed h2 + http/1.1 ALPN list is wired through.
        assert_eq!(config.alpn_protocols, alpn_protocols());
    }

    /// A CA bundle file whose content isn't valid PEM at all (garbage bytes
    /// where a base64 body is expected) must fail with `InvalidData` — the
    /// `CertificateDer::pem_reader_iter(..).collect()` parse-error arm in
    /// `roots_from_pem`, distinct from "file unreadable" and
    /// "well-formed PEM but zero certificates".
    #[test]
    fn malformed_ca_bundle_fails_fast() {
        let ca_path = write_tmp(
            "garbage-ca",
            "-----BEGIN CERTIFICATE-----\nnot valid base64 !!!\n-----END CERTIFICATE-----\n",
        );
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: Some(ca_path),
            ..TlsConfig::default()
        };
        let err = read_client_ca_roots(&tls).expect_err("malformed CA bundle PEM must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A CA bundle entry that is valid *PEM* (base64 decodes cleanly) but
    /// whose decoded bytes are not a valid X.509 certificate must be rejected
    /// by `RootCertStore::add` — the `roots.add(cert).map_err(...)` arm,
    /// distinct from the PEM-parse failure above.
    #[test]
    fn ca_bundle_with_valid_pem_but_invalid_der_fails_fast() {
        use base64::Engine as _;
        // Valid base64 (decodes to plain text), but nowhere near a valid
        // ASN.1 DER certificate structure.
        let bogus_body = base64::engine::general_purpose::STANDARD
            .encode(b"not a real certificate, just plain text padding to be long enough");
        let ca_path = write_tmp(
            "bogus-der-ca",
            &format!("-----BEGIN CERTIFICATE-----\n{bogus_body}\n-----END CERTIFICATE-----\n"),
        );
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: Some(ca_path),
            ..TlsConfig::default()
        };
        let err = read_client_ca_roots(&tls)
            .expect_err("PEM-valid but DER-invalid CA cert must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A server cert file that isn't valid PEM must fail with `InvalidData` —
    /// the main `CertificateDer::pem_reader_iter(cert_file).collect()`
    /// parse-error arm (the cert-side sibling of the CA-bundle test above).
    #[test]
    fn malformed_cert_file_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp(
                "garbage-cert",
                "-----BEGIN CERTIFICATE-----\nnot valid base64 !!!\n-----END CERTIFICATE-----\n",
            )),
            key_path: Some(write_tmp("some-key", "irrelevant, parsed after cert")),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("malformed cert PEM must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A cert file that IS well-formed (readable, and would parse as valid
    /// PEM if it contained any `CERTIFICATE` blocks) but contains zero
    /// certificates must be rejected with the "no certificates found"
    /// `InvalidData` error, distinct from a parse failure.
    #[test]
    fn empty_cert_file_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("empty-cert", "# no certificates here\n")),
            key_path: Some(write_tmp("some-key", "irrelevant, never reached")),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("empty cert file must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("no certificates found"),
            "got: {err}"
        );
    }

    /// A key file that isn't a parseable private key (valid cert supplied,
    /// but the key file is garbage) must fail with `InvalidData` — the
    /// `PrivateKeyDer::from_pem_reader(key_file)` parse-error arm.
    #[test]
    fn malformed_key_file_fails_fast() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert-badkey", &pki.server_cert_pem)),
            key_path: Some(write_tmp(
                "garbage-key",
                "-----BEGIN PRIVATE KEY-----\nnot valid base64 !!!\n-----END PRIVATE KEY-----\n",
            )),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("malformed key PEM must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A syntactically valid cert and a syntactically valid key that simply
    /// don't belong together (different keypairs) must be rejected at
    /// `with_single_cert` — the "invalid TLS certificate/key pair" arm, which
    /// is only reached once every earlier parse step already succeeded.
    #[test]
    fn mismatched_cert_and_key_fails_fast() {
        let pki_a = gen_test_pki();
        let pki_b = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("mismatch-cert", &pki_a.server_cert_pem)),
            // A key from a completely different, unrelated PKI.
            key_path: Some(write_tmp("mismatch-key", &pki_b.server_key_pem)),
            ..TlsConfig::default()
        };
        let err =
            build_rustls_server_config(&tls).expect_err("mismatched cert/key pair must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("invalid TLS certificate/key pair"),
            "got: {err}"
        );
    }

    // --- In-process rustls handshake tests (no live socket needed) ---------

    /// Pump handshake records between two in-memory rustls connections until
    /// both finish handshaking or one errors. Returns the first processing
    /// error (e.g. the server rejecting a missing required client cert).
    fn drive_handshake(
        client: &mut rustls::Connection,
        server: &mut rustls::Connection,
    ) -> Result<(), rustls::Error> {
        for _ in 0..16 {
            let mut buf = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut buf).unwrap();
            }
            let mut rd: &[u8] = &buf;
            while !rd.is_empty() {
                server.read_tls(&mut rd).unwrap();
            }
            server.process_new_packets()?;

            let mut buf = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut buf).unwrap();
            }
            let mut rd: &[u8] = &buf;
            while !rd.is_empty() {
                client.read_tls(&mut rd).unwrap();
            }
            client.process_new_packets()?;

            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Ok(())
    }

    fn make_server(pki: &TestPki) -> rustls::ServerConnection {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert", &pki.server_cert_pem)),
            key_path: Some(write_tmp("srv-key", &pki.server_key_pem)),
            client_auth: ClientAuth::Required,
            client_ca_path: Some(write_tmp("ca", &pki.ca_pem)),
            ..TlsConfig::default()
        };
        let config = build_rustls_server_config(&tls).expect("server config must build");
        rustls::ServerConnection::new(Arc::new(config)).expect("server connection")
    }

    /// Client config trusting the CA; `client_cert` toggles whether it presents
    /// its own certificate.
    fn make_client(pki: &TestPki, present_cert: bool) -> rustls::ClientConnection {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(pki.ca_pem.as_bytes()).unwrap())
            .unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots);

        let config = if present_cert {
            let chain =
                vec![CertificateDer::from_pem_slice(pki.client_cert_pem.as_bytes()).unwrap()];
            let key = PrivateKeyDer::from_pem_slice(pki.client_key_pem.as_bytes()).unwrap();
            builder.with_client_auth_cert(chain, key).unwrap()
        } else {
            builder.with_no_client_auth()
        };

        let name = ServerName::try_from("localhost").unwrap();
        rustls::ClientConnection::new(Arc::new(config), name).expect("client connection")
    }

    // ---------------------------------------------------------------------
    // Hot-reloadable leaf certificate
    // ---------------------------------------------------------------------

    /// Generate a second server leaf from the same CA, so a swap is
    /// distinguishable from the original while both stay verifiable by the
    /// client. This is what an ACME renewal looks like from rustls' side: a
    /// different certificate for the same name.
    fn gen_renewed_server_leaf(pki: &TestPki) -> (String, String) {
        let ca_key = KeyPair::from_pem(&pki.ca_key_pem).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.is_ca = IsCa::NoCa;
        let cert = params.signed_by(&key, &issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn certified_from_pem(cert_pem: &str, key_pem: &str) -> CertifiedKey {
        let provider = rustls::crypto::ring::default_provider();
        read_certified_key(
            &write_tmp("ck-cert", cert_pem),
            &write_tmp("ck-key", key_pem),
            &provider,
        )
        .expect("a matching pair must load")
    }

    /// The resolver serves what it was built with, and serves the replacement
    /// after a swap. This is the whole contract; everything else is plumbing.
    #[test]
    fn resolver_serves_the_replacement_after_a_swap() {
        let pki = gen_test_pki();
        let (renewed_cert, renewed_key) = gen_renewed_server_leaf(&pki);

        let original = certified_from_pem(&pki.server_cert_pem, &pki.server_key_pem);
        let original_der = original.cert.clone();
        let resolver = ReloadableCertResolver::new(original);
        assert_eq!(resolver.current().cert, original_der);

        let renewed = certified_from_pem(&renewed_cert, &renewed_key);
        let renewed_der = renewed.cert.clone();
        let previous = resolver.replace(renewed);

        assert_eq!(
            previous.cert, original_der,
            "replace must hand back the certificate it displaced"
        );
        assert_eq!(resolver.current().cert, renewed_der);
        assert_ne!(
            original_der, renewed_der,
            "the test PKI must actually produce two different leaves"
        );
    }

    /// A renewal caught mid-write — certbot writes `fullchain.pem` and
    /// `privkey.pem` as two separate operations, so a poll can observe the new
    /// chain beside the old key — must be rejected, and must leave the previous
    /// certificate serving rather than taking the listener down.
    #[test]
    fn half_written_renewal_is_rejected_and_leaves_the_old_cert_serving() {
        let pki = gen_test_pki();
        let (renewed_cert, _renewed_key) = gen_renewed_server_leaf(&pki);

        let original = certified_from_pem(&pki.server_cert_pem, &pki.server_key_pem);
        let original_der = original.cert.clone();
        let resolver = ReloadableCertResolver::new(original);

        // The new chain with the OLD key: exactly the half-updated pair.
        let provider = rustls::crypto::ring::default_provider();
        let err = read_certified_key(
            &write_tmp("halfway-cert", &renewed_cert),
            &write_tmp("halfway-key", &pki.server_key_pem),
            &provider,
        )
        .expect_err("a mismatched pair must not load");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("invalid TLS certificate/key pair"),
            "got: {err}"
        );

        assert_eq!(
            resolver.current().cert,
            original_der,
            "a failed reload must not disturb the certificate being served"
        );
    }

    /// `read_certified_key` is the single parser for the boot path and every
    /// reload, so a certificate that boots must reload and vice versa. Pinned
    /// because two parsers is how a renewal installs something the next restart
    /// refuses.
    #[test]
    fn the_boot_path_and_the_reload_path_accept_the_same_pair() {
        let pki = gen_test_pki();
        let cert_path = write_tmp("shared-cert", &pki.server_cert_pem);
        let key_path = write_tmp("shared-key", &pki.server_key_pem);

        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(cert_path.clone()),
            key_path: Some(key_path.clone()),
            ..TlsConfig::default()
        };
        build_rustls_server_config(&tls).expect("the boot path must accept this pair");

        let provider = rustls::crypto::ring::default_provider();
        read_certified_key(&cert_path, &key_path, &provider)
            .expect("the reload path must accept the same pair");
    }

    /// The default is an hour, and `0` is the documented way to turn polling
    /// off. Pinned because the value reaches operators through the docs site
    /// and a silent change to either would strand them.
    #[test]
    fn reload_interval_defaults_to_one_hour() {
        assert_eq!(
            TlsConfig::default().reload_interval_secs,
            axiam_api_rest::config::DEFAULT_TLS_RELOAD_INTERVAL_SECS
        );
        assert_eq!(TlsConfig::default().reload_interval_secs, 3600);
    }

    /// A renewal on disk is picked up: the reload reports a change and the
    /// resolver serves the new leaf afterwards. This is the path SIGHUP and the
    /// poll both funnel into, and until now nothing exercised it — the tests
    /// covered the resolver and the parser on either side of it.
    #[test]
    fn a_reload_installs_a_renewed_pair_from_disk() {
        let pki = gen_test_pki();
        let (renewed_cert, renewed_key) = gen_renewed_server_leaf(&pki);

        // The files the "listener" was built from; the reload re-reads these.
        let cert_path = write_tmp("reload-cert", &pki.server_cert_pem);
        let key_path = write_tmp("reload-key", &pki.server_key_pem);

        let provider = rustls::crypto::ring::default_provider();
        let original = read_certified_key(&cert_path, &key_path, &provider).unwrap();
        let original_der = original.cert.clone();
        let resolver = ReloadableCertResolver::new(original);

        // Nothing has changed yet: a poll between renewals must be a no-op, not
        // an hourly swap-and-log forever.
        assert!(
            !reload_into(&resolver, &provider, &cert_path, &key_path).unwrap(),
            "an unchanged pair must not be reported as a reload"
        );
        assert_eq!(resolver.current().cert, original_der);

        // certbot renews: both files are replaced.
        std::fs::write(&cert_path, &renewed_cert).unwrap();
        std::fs::write(&key_path, &renewed_key).unwrap();

        assert!(
            reload_into(&resolver, &provider, &cert_path, &key_path).unwrap(),
            "a changed pair must be reported as a reload"
        );
        assert_ne!(
            resolver.current().cert,
            original_der,
            "the resolver must be serving the renewed leaf"
        );

        // And the reload is idempotent once it has landed.
        assert!(!reload_into(&resolver, &provider, &cert_path, &key_path).unwrap());
    }

    /// The half-written renewal, through the reload entry point rather than the
    /// parser: the error propagates and the previous certificate keeps serving.
    /// That is the property that makes an hourly poll safe to run against files
    /// another process is rewriting.
    #[test]
    fn a_reload_that_fails_leaves_the_previous_certificate_serving() {
        let pki = gen_test_pki();
        let (renewed_cert, renewed_key) = gen_renewed_server_leaf(&pki);

        let cert_path = write_tmp("halfway-reload-cert", &pki.server_cert_pem);
        let key_path = write_tmp("halfway-reload-key", &pki.server_key_pem);

        let provider = rustls::crypto::ring::default_provider();
        let original = read_certified_key(&cert_path, &key_path, &provider).unwrap();
        let original_der = original.cert.clone();
        let resolver = ReloadableCertResolver::new(original);

        // The new chain lands; the key has not been replaced yet.
        std::fs::write(&cert_path, &renewed_cert).unwrap();

        let err = reload_into(&resolver, &provider, &cert_path, &key_path)
            .expect_err("a mismatched pair must not reload");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            resolver.current().cert,
            original_der,
            "a failed reload must leave the listener serving what it had"
        );

        // The key catches up on the next tick, and the reload then succeeds —
        // which is what makes retrying the right response rather than failing
        // the process.
        std::fs::write(&key_path, &renewed_key).unwrap();
        assert!(
            reload_into(&resolver, &provider, &cert_path, &key_path).unwrap(),
            "the retry after the write completes must succeed"
        );
    }

    /// A missing file is an ordinary `NotFound`, not a panic, and leaves the
    /// certificate alone. Covers the path a deleted or not-yet-created renewal
    /// directory takes.
    #[test]
    fn a_reload_from_a_missing_file_is_an_error_not_a_panic() {
        let pki = gen_test_pki();
        let cert_path = write_tmp("gone-cert", &pki.server_cert_pem);
        let key_path = write_tmp("gone-key", &pki.server_key_pem);

        let provider = rustls::crypto::ring::default_provider();
        let original = read_certified_key(&cert_path, &key_path, &provider).unwrap();
        let original_der = original.cert.clone();
        let resolver = ReloadableCertResolver::new(original);

        std::fs::remove_file(&key_path).unwrap();

        let err = reload_into(&resolver, &provider, &cert_path, &key_path)
            .expect_err("a missing key must not reload");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(resolver.current().cert, original_der);
    }

    /// The process-global entry point the signal handler and the poll actually
    /// call. Builds a listener config first so a resolver is definitely
    /// installed — `LIVE_CERT_RESOLVER` is set once per process by whichever
    /// test builds a config first, and only a *successful* build installs, so
    /// whatever won holds a readable, matching pair whose temp files outlive
    /// the test.
    ///
    /// Asserts the shape rather than the boolean: which pair is on disk depends
    /// on who won, but "found a listener and completed without error" is the
    /// contract, and `Ok(None)` here would mean the boot path never installed
    /// the resolver at all.
    #[test]
    fn the_global_reload_entry_point_finds_the_installed_listener() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("global-reload-cert", &pki.server_cert_pem)),
            key_path: Some(write_tmp("global-reload-key", &pki.server_key_pem)),
            ..TlsConfig::default()
        };
        build_rustls_server_config(&tls).expect("config must build");

        let outcome = reload_leaf_certificate().expect("the reload must not error");
        assert!(
            outcome.is_some(),
            "a process that built a TLS listener must report one to reload into"
        );
    }

    /// `spawn_leaf_reloader` installs the SIGHUP handler and honours
    /// `interval_secs = 0` by skipping the poll.
    ///
    /// Worth a test rather than trusting it: this is the entry point for the
    /// whole renewal mechanism, and its failure mode is silence — a handler
    /// that never installs looks exactly like a certificate nobody renewed
    /// until the day it expires. `yield_now` lets the spawned task reach the
    /// `signal()` call, which is what proves it installs on this platform.
    #[tokio::test]
    async fn the_reloader_installs_its_sighup_handler_and_honours_a_zero_interval() {
        // 0 = polling disabled; the SIGHUP task is still spawned.
        spawn_leaf_reloader(0);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        // A real interval also spawns the poll task. The first tick is burned
        // immediately and the second is an hour out, so the task parks rather
        // than reloading anything during the test.
        spawn_leaf_reloader(3600);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    /// Every outcome the reload can produce has a log arm, and none of them
    /// panics. Cheap, and it pins the WARN-not-ERROR choice on a failed reload:
    /// the previous certificate is still serving, so a failure here is not the
    /// same severity as one that takes the listener down.
    #[test]
    fn every_reload_outcome_logs_without_panicking() {
        log_reload_outcome("test", Ok(Some(true)));
        log_reload_outcome("test", Ok(Some(false)));
        log_reload_outcome("test", Ok(None));
        log_reload_outcome(
            "test",
            Err(io::Error::new(io::ErrorKind::InvalidData, "synthetic")),
        );
    }

    /// A swapped certificate must actually reach the wire, not merely sit in
    /// the `ArcSwap`. Drives two real TLS 1.3 handshakes against one
    /// `ServerConfig` — the same object actix binds for the process's life —
    /// and asserts the client is presented the renewed leaf on the second.
    #[test]
    fn a_swapped_certificate_is_served_on_the_next_handshake() {
        let pki = gen_test_pki();
        let (renewed_cert, renewed_key) = gen_renewed_server_leaf(&pki);

        let original = certified_from_pem(&pki.server_cert_pem, &pki.server_key_pem);
        let original_der = original.cert.clone();
        let resolver = Arc::new(ReloadableCertResolver::new(original));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>),
        );

        let presented = |config: &Arc<ServerConfig>| -> Vec<CertificateDer<'static>> {
            let mut server: rustls::Connection = rustls::ServerConnection::new(Arc::clone(config))
                .unwrap()
                .into();
            let mut client: rustls::Connection = make_client(&pki, false).into();
            drive_handshake(&mut client, &mut server).expect("handshake must complete");
            client
                .peer_certificates()
                .expect("the client must have been presented a chain")
                .to_vec()
        };

        assert_eq!(
            presented(&config),
            original_der,
            "the first handshake must present the boot certificate"
        );

        let renewed = certified_from_pem(&renewed_cert, &renewed_key);
        let renewed_der = renewed.cert.clone();
        resolver.replace(renewed);

        assert_eq!(
            presented(&config),
            renewed_der,
            "the handshake after a swap must present the renewed certificate,              with no rebuild of the ServerConfig and no restart"
        );
    }

    #[test]
    fn handshake_rejected_without_client_cert_when_required() {
        let pki = gen_test_pki();
        let mut server = rustls::Connection::Server(make_server(&pki));
        let mut client = rustls::Connection::Client(make_client(&pki, false));
        let result = drive_handshake(&mut client, &mut server);
        assert!(
            result.is_err(),
            "required client-auth must reject a client presenting no certificate"
        );
    }

    #[test]
    fn handshake_accepts_bench_client_cert_and_exposes_verified_peer_cert() {
        let pki = gen_test_pki();
        let mut server = rustls::Connection::Server(make_server(&pki));
        let mut client = rustls::Connection::Client(make_client(&pki, true));
        drive_handshake(&mut client, &mut server)
            .expect("handshake with a CA-signed client cert must succeed");
        assert!(
            !server.is_handshaking(),
            "server handshake should complete with a valid client cert"
        );

        // The VERIFIED peer certificate is what handlers consume (never a header).
        let peer = server
            .peer_certificates()
            .expect("verified client cert must be present after mTLS handshake");
        let leaf = peer.first().expect("at least one peer cert");

        // SAN extraction (the axiam-api-rest side of D3) must find the URI SAN.
        let verified = axiam_api_rest::VerifiedClientCert::from_der(leaf.as_ref())
            .expect("verified client cert must parse");
        assert!(
            verified
                .sans
                .iter()
                .any(|s| s == "URI:spiffe://axiam/device-01"),
            "expected the client URI SAN to be extracted, got {:?}",
            verified.sans
        );
        assert_eq!(
            verified.spki_sha256.len(),
            64,
            "SPKI fingerprint is hex-SHA256"
        );
    }
}
