//! The audit dead-letter file: where an audit row goes when the datastore did
//! not take it (T19.27, T-108).
//!
//! One file, named by `AXIAM__GDPR_AUDIT_DLQ_FILE`, append-only, one
//! [`CreateAuditLogEntry`] as JSON per line. That line is the replayable form:
//! an operator (or a later replay job) reads each line back into a
//! `CreateAuditLogEntry` and appends it once the datastore is healthy. The GDPR
//! records' dead letter (`write_audit_with_dead_letter`) and the
//! request-audit worker's both write it, through [`encode_line`], so the two
//! cannot drift apart.
//!
//! Two ways in:
//!
//! - [`append_blocking`] writes the line before it returns. For a caller that is
//!   already off the request path and wants the guarantee, such as the cleanup
//!   sweep's erasure record.
//! - [`DeadLetterWriter`] queues the row and returns at once; a writer task owns
//!   the file. For a caller that must not wait on file I/O — the request-audit
//!   middleware, whose only reason to dead-letter is that the system is under
//!   pressure.
//!
//! # The budget (R1W2-02)
//!
//! The file is bounded by [`MAX_BYTES_ENV`] ([`DEFAULT_MAX_BYTES`], 192 MiB, by
//! default). Request-audit rows may fill the first nine tenths of it
//! ([`request_row_limit`]); past that they are refused, counted as not
//! recoverable, and the writer reports itself [full](DeadLetterWriter::is_full).
//! The last tenth is a reserve only [`append_blocking`] — the GDPR records —
//! writes into, so an erasure record is not refused because a flood of request
//! rows got there first. Unbounded, the file filled the disk the datastore needs
//! (Compose) or crossed its volume's `sizeLimit`, which Kubernetes enforces by
//! evicting the pod and deleting the volume with the file in it.
//!
//! A request row's attacker-chosen fields — the path in `action`, the
//! client-supplied address in `ip_address` — are cut to [`MAX_ACTION_BYTES`]
//! and [`MAX_ADDRESS_BYTES`] in every line ([`encode_line`]), so a line is
//! about a kilobyte at most whatever the request carried.

use std::borrow::Cow;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use axiam_core::models::audit::CreateAuditLogEntry;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{mpsc, oneshot};

/// Environment variable naming the dead-letter file. Intended to point at a
/// mounted volume so the file survives a restart. Unset (or empty) means no file
/// is written and a lost row is counted and logged only.
pub const DEAD_LETTER_FILE_ENV: &str = "AXIAM__GDPR_AUDIT_DLQ_FILE";

/// Environment variable bounding the dead-letter file, in bytes (R1W2-02).
/// Unset (or empty) means [`DEFAULT_MAX_BYTES`]. Keep it below the limit of the
/// volume the file is on.
pub const MAX_BYTES_ENV: &str = "AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES";

/// The budget when [`MAX_BYTES_ENV`] is unset: 192 MiB, below the shipped
/// Kubernetes volume's 256 MiB `sizeLimit`.
pub const DEFAULT_MAX_BYTES: u64 = 192 * 1024 * 1024;

/// The smallest budget [`MAX_BYTES_ENV`] may set: 1 MiB, a thousand request
/// rows or so. Below it the file is full before it is useful.
pub const MIN_MAX_BYTES: u64 = 1024 * 1024;

/// The longest `action` a line carries, in bytes. A request row's action is
/// `"{method} {path}"`, and the path is the client's to choose.
pub const MAX_ACTION_BYTES: usize = 512;

/// The longest `ip_address` a line carries, in bytes: an IPv6 literal with a
/// zone and a port fits. The value is the client's `Forwarded` /
/// `X-Forwarded-For` header where a proxy is trusted, and unvalidated.
pub const MAX_ADDRESS_BYTES: usize = 64;

/// What replaces the cut end of a field that was longer than its bound.
const TRUNCATED: &str = "...[truncated]";

/// Rows the writer task may hold before [`DeadLetterWriter::submit`] refuses
/// one. Bounded so a slow volume cannot grow memory without limit while the
/// datastore is also down; a row refused here is counted as unrecoverable.
const QUEUE_CAPACITY: usize = 1024;

/// Rows written per file write, so a burst costs one syscall rather than one
/// per row.
const BATCH: usize = 64;

/// The budget [`MAX_BYTES_ENV`] sets: [`DEFAULT_MAX_BYTES`] when it is unset or
/// empty, an error naming the variable when it is not a whole number of bytes
/// of at least [`MIN_MAX_BYTES`].
pub fn max_bytes_from_env() -> Result<u64, String> {
    match std::env::var(MAX_BYTES_ENV) {
        Ok(v) if !v.trim().is_empty() => parse_max_bytes(&v),
        _ => Ok(DEFAULT_MAX_BYTES),
    }
}

fn parse_max_bytes(value: &str) -> Result<u64, String> {
    match value.trim().parse::<u64>() {
        Ok(n) if n >= MIN_MAX_BYTES => Ok(n),
        Ok(n) => Err(format!(
            "{MAX_BYTES_ENV}={n} is below the minimum of {MIN_MAX_BYTES} bytes"
        )),
        Err(_) => Err(format!(
            "{MAX_BYTES_ENV}={value:?} is not a whole number of bytes"
        )),
    }
}

/// How much of a `max_bytes` budget request-audit rows may fill: nine tenths.
/// The rest is the GDPR records' reserve.
pub fn request_row_limit(max_bytes: u64) -> u64 {
    max_bytes - max_bytes / 10
}

/// `value`, cut to at most `max` bytes (on a character boundary) with a marker
/// when it was longer.
fn bounded(value: &str, max: usize) -> Cow<'_, str> {
    if value.len() <= max {
        return Cow::Borrowed(value);
    }
    let mut end = max.saturating_sub(TRUNCATED.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!("{}{TRUNCATED}", &value[..end]))
}

/// `entry` with its client-sized fields cut to [`MAX_ACTION_BYTES`] and
/// [`MAX_ADDRESS_BYTES`]. The audit middleware applies it to the row it
/// records, so the datastore row and the dead-letter line agree.
pub fn bound_fields(entry: &mut CreateAuditLogEntry) {
    if let Cow::Owned(action) = bounded(&entry.action, MAX_ACTION_BYTES) {
        entry.action = action;
    }
    if let Some(ip) = &entry.ip_address
        && let Cow::Owned(cut) = bounded(ip, MAX_ADDRESS_BYTES)
    {
        entry.ip_address = Some(cut);
    }
}

/// One dead-letter line, without its newline. The client-sized fields are
/// bounded (see [`bound_fields`]) whoever built the entry.
pub fn encode_line(entry: &CreateAuditLogEntry) -> serde_json::Result<String> {
    let oversized = entry.action.len() > MAX_ACTION_BYTES
        || entry
            .ip_address
            .as_ref()
            .is_some_and(|ip| ip.len() > MAX_ADDRESS_BYTES);
    if oversized {
        let mut entry = entry.clone();
        bound_fields(&mut entry);
        serde_json::to_string(&entry)
    } else {
        serde_json::to_string(entry)
    }
}

/// Append `entry` to the file at `path` and return when it has been written.
///
/// Opens with `append(true)`: an existing file is never truncated or rewritten.
/// Blocks on file I/O, so not for the request path — see [`DeadLetterWriter`].
///
/// For the GDPR records: it may write into the reserve above the request rows'
/// share, up to the whole of `max_bytes`, and refuses a line that would cross
/// it (an error of kind `StorageFull`). The check reads the file's size before
/// the write, so a batch the writer task appends at the same moment can take
/// the file past `max_bytes` by that batch.
pub fn append_blocking(
    path: &Path,
    entry: &CreateAuditLogEntry,
    max_bytes: u64,
) -> std::io::Result<()> {
    let mut line = encode_line(entry).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let size = file.metadata()?.len();
    if size + line.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            format!(
                "the audit dead-letter file holds {size} bytes and its budget is {max_bytes} \
                 ({MAX_BYTES_ENV}); replay and move it"
            ),
        ));
    }
    file.write_all(line.as_bytes())
}

/// What [`DeadLetterWriter::submit`] did with a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submitted {
    /// Queued for the writer task. It is in the file once the task has run; a
    /// write that then fails is counted in [`DeadLetterWriter::lost`].
    Queued,
    /// No file is configured; the row is not kept anywhere.
    NotConfigured,
    /// The writer's queue is full (or its task is gone); the row is not kept.
    Overflow,
    /// The file has reached the request rows' share of its budget; the row is
    /// not kept.
    Full,
}

enum Msg {
    Entry(CreateAuditLogEntry),
    Flush(oneshot::Sender<()>),
}

#[derive(Default)]
struct Counts {
    written: AtomicU64,
    lost: AtomicU64,
    /// Of `lost`, the rows refused because the file was full.
    refused_full: AtomicU64,
    /// Whether the file has reached the request rows' share of its budget.
    full: AtomicBool,
}

struct Inner {
    tx: mpsc::Sender<Msg>,
    counts: Arc<Counts>,
}

/// A non-blocking front for the dead-letter file.
///
/// [`Self::submit`] never waits: it puts the row on a bounded queue read by one
/// task, which batches the rows and appends them. Cloning shares the queue.
/// `disabled()` is the writer of a deployment that configured no file.
#[derive(Clone, Default)]
pub struct DeadLetterWriter {
    inner: Option<Arc<Inner>>,
}

impl DeadLetterWriter {
    /// A writer that keeps nothing: every [`Self::submit`] is `NotConfigured`.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// The writer [`DEAD_LETTER_FILE_ENV`] names, bounded by [`MAX_BYTES_ENV`],
    /// or a disabled one when the file is unset or empty. An invalid budget is
    /// an error, so a typo fails the boot rather than unbounding the file.
    /// Spawns the writer task, so call it inside a runtime.
    pub fn from_env() -> Result<Self, String> {
        let max_bytes = max_bytes_from_env()?;
        Ok(match std::env::var_os(DEAD_LETTER_FILE_ENV) {
            Some(path) if !path.is_empty() => {
                Self::spawn_with_budget(PathBuf::from(path), max_bytes)
            }
            _ => Self::disabled(),
        })
    }

    /// Write to `path`, creating it when absent and appending when present,
    /// within [`DEFAULT_MAX_BYTES`]. Spawns the writer task, so call it inside a
    /// runtime.
    pub fn spawn(path: impl Into<PathBuf>) -> Self {
        Self::spawn_with_budget(path, DEFAULT_MAX_BYTES)
    }

    /// As [`Self::spawn`], within `max_bytes`: request rows fill at most
    /// [`request_row_limit`] of it.
    pub fn spawn_with_budget(path: impl Into<PathBuf>, max_bytes: u64) -> Self {
        let path = path.into();
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let counts = Arc::new(Counts::default());
        let limit = request_row_limit(max_bytes);
        // A file left full by an earlier run is reported full from the start,
        // not from the first row it refuses.
        if std::fs::metadata(&path).is_ok_and(|m| m.len() >= limit) {
            counts.full.store(true, Ordering::Relaxed);
        }
        tokio::spawn(write_task(path, limit, rx, Arc::clone(&counts)));
        Self {
            inner: Some(Arc::new(Inner { tx, counts })),
        }
    }

    /// Whether a file is configured.
    pub fn is_configured(&self) -> bool {
        self.inner.is_some()
    }

    /// Queue `entry` for the file. Never blocks and never does I/O.
    pub fn submit(&self, entry: CreateAuditLogEntry) -> Submitted {
        let Some(inner) = &self.inner else {
            return Submitted::NotConfigured;
        };
        // The file does not shrink while the server runs (it is moved only with
        // the server stopped), so once full it stays full.
        if inner.counts.full.load(Ordering::Relaxed) {
            inner.counts.lost.fetch_add(1, Ordering::Relaxed);
            inner.counts.refused_full.fetch_add(1, Ordering::Relaxed);
            return Submitted::Full;
        }
        match inner.tx.try_send(Msg::Entry(entry)) {
            Ok(()) => Submitted::Queued,
            Err(_) => {
                inner.counts.lost.fetch_add(1, Ordering::Relaxed);
                Submitted::Overflow
            }
        }
    }

    /// Rows this writer has appended to the file since start.
    pub fn written(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |i| i.counts.written.load(Ordering::Relaxed))
    }

    /// Rows this writer was given and could not keep since start: refused for
    /// want of queue room or because the file was full, or queued and then not
    /// written (the file could not be opened or written).
    pub fn lost(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |i| i.counts.lost.load(Ordering::Relaxed))
    }

    /// Of [`Self::lost`], the rows refused because the file had reached the
    /// request rows' share of its budget.
    pub fn refused_full(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |i| i.counts.refused_full.load(Ordering::Relaxed))
    }

    /// Whether the file has reached the request rows' share of its budget, so
    /// every further request row is refused until it is replayed and moved.
    pub fn is_full(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|i| i.counts.full.load(Ordering::Relaxed))
    }

    /// Wait, at most `within`, until every row submitted before this call has
    /// been through the writer. `true` when there is nothing to wait for.
    pub async fn flush(&self, within: Duration) -> bool {
        let Some(inner) = &self.inner else {
            return true;
        };
        let (done, reached) = oneshot::channel();
        let wait = async {
            inner.tx.send(Msg::Flush(done)).await.ok()?;
            reached.await.ok()
        };
        matches!(tokio::time::timeout(within, wait).await, Ok(Some(())))
    }
}

async fn write_task(path: PathBuf, limit: u64, mut rx: mpsc::Receiver<Msg>, counts: Arc<Counts>) {
    let mut file: Option<tokio::fs::File> = None;
    // Logged on the way into failure, not per batch: a volume that is gone
    // would otherwise add a line per burst to a log that is already busy.
    let mut failing = false;
    while let Some(first) = rx.recv().await {
        let mut lines: Vec<String> = Vec::new();
        let mut flushes = Vec::new();
        let mut next = Some(first);
        while let Some(msg) = next.take() {
            match msg {
                Msg::Entry(entry) => match encode_line(&entry) {
                    Ok(mut line) => {
                        line.push('\n');
                        lines.push(line);
                    }
                    Err(e) => {
                        counts.lost.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(error = %e, "audit dead-letter record could not be encoded");
                    }
                },
                Msg::Flush(done) => flushes.push(done),
            }
            if lines.len() < BATCH {
                next = rx.try_recv().ok();
            }
        }
        if !lines.is_empty() {
            match append(&path, &mut file, limit, &lines).await {
                Ok(appended) => {
                    counts
                        .written
                        .fetch_add(appended.written, Ordering::Relaxed);
                    failing = false;
                    if appended.refused > 0 {
                        counts.lost.fetch_add(appended.refused, Ordering::Relaxed);
                        counts
                            .refused_full
                            .fetch_add(appended.refused, Ordering::Relaxed);
                        if !counts.full.swap(true, Ordering::Relaxed) {
                            tracing::error!(
                                path = %path.display(),
                                env_var = MAX_BYTES_ENV,
                                limit_bytes = limit,
                                "audit dead-letter file is full — request-audit rows are now \
                                 refused (counted as not_recoverable on /health/jobs); the GDPR \
                                 records keep a reserve above this. Replay the file, then move \
                                 it with the server stopped"
                            );
                        }
                    }
                }
                Err(e) => {
                    // A handle that failed may be a dead one; reopen next time.
                    file = None;
                    counts.lost.fetch_add(lines.len() as u64, Ordering::Relaxed);
                    if !failing {
                        failing = true;
                        tracing::error!(
                            error = %e,
                            path = %path.display(),
                            env_var = DEAD_LETTER_FILE_ENV,
                            "audit dead-letter file cannot be written — rows that were headed \
                             for it are lost (counted as not_recoverable on /health/jobs)"
                        );
                    }
                }
            }
        }
        for done in flushes {
            let _ = done.send(());
        }
    }
}

/// What one batch did.
struct Appended {
    written: u64,
    /// Lines that would have taken the file past the request rows' limit.
    refused: u64,
}

/// Append, in order, each of the `lines` that still fits under `limit`; refuse
/// the others. The file's size is read before each batch, so the GDPR records'
/// own writes (through [`append_blocking`]) count against the limit too.
async fn append(
    path: &Path,
    file: &mut Option<tokio::fs::File>,
    limit: u64,
    lines: &[String],
) -> std::io::Result<Appended> {
    if file.is_none() {
        *file = Some(
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?,
        );
    }
    let f = file.as_mut().expect("opened above");
    let mut size = f.metadata().await?.len();
    let mut bytes = String::new();
    let mut written = 0;
    for line in lines {
        let len = line.len() as u64;
        if size + len > limit {
            continue;
        }
        size += len;
        bytes.push_str(line);
        written += 1;
    }
    if written > 0 {
        f.write_all(bytes.as_bytes()).await?;
        f.flush().await?;
    }
    Ok(Appended {
        written,
        refused: lines.len() as u64 - written,
    })
}
