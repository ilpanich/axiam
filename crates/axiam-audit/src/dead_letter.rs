//! The audit dead-letter file: where an audit row goes when the datastore did
//! not take it (T19.27, T-108).
//!
//! One file, named by `AXIAM__GDPR_AUDIT_DLQ_FILE`, append-only, one
//! [`DeadLetterRecord`] as JSON per line:
//! `{"occurred_at": …, "reason": …, "entry": {…}}`. The `entry` is the
//! replayable [`CreateAuditLogEntry`]: an operator (or a later replay job)
//! reads each line back with [`decode_line`] and appends the entry once the
//! datastore is healthy. The GDPR records' dead letter
//! (`write_audit_with_dead_letter`) and the request-audit worker's both write
//! it, through [`encode_line`], so the two cannot drift apart.
//!
//! # When, and why (#595)
//!
//! A bare entry has no timestamp, and the replay creates the row at replay
//! time, so the trail lost when the event happened and its order against the
//! rows written normally. The envelope carries both:
//!
//! - `occurred_at` is when the event happened, captured where the entry is
//!   produced and carried with it, never when a writer flushes it. For a
//!   request-audit row it is the moment the response finished and the audit
//!   entry was built (the middleware, before the row is queued); for a GDPR
//!   record it is the moment the record was handed to
//!   `write_audit_with_dead_letter`, which is right after the action it
//!   records and before the datastore write that was then refused.
//! - `reason` is a [`DeadLetterReason`]: a closed set of short names, never an
//!   error's text (which can carry a query, an identifier, or a secret).
//!
//! [`decode_line`] reads the earlier, bare form too, with neither field.
//!
//! Two ways in:
//!
//! - [`append_blocking`] and [`append_off_thread`] write the line, and sync it
//!   to the device, before they return. For a caller that wants the guarantee:
//!   the cleanup sweep's erasure record and the GDPR request records. The
//!   first blocks its thread on file I/O; a request handler uses the second,
//!   which runs the same write on the runtime's blocking pool (#594).
//! - [`DeadLetterWriter`] queues the row and returns at once; a writer task owns
//!   the file. For a caller that must not wait on file I/O — the request-audit
//!   middleware, whose only reason to dead-letter is that the system is under
//!   pressure. The task syncs the file's data after each batch it writes.
//!
//! # Durability and mode (#594)
//!
//! Each line is one `write_all` of the line and its newline, so two records
//! never share a line. A write that has returned has also been through
//! `sync_data`: a host crash does not take it back. (The file's directory entry
//! is not synced separately, so a crash right after the file was first created
//! can still lose the file itself.) Both openers create the file with mode
//! `0600` on Unix rather than the process umask's, and tighten an existing
//! file that is readable by group or others to `0600` when they open it (a
//! failure to do so is logged, not fatal: the record is still written). The
//! lines carry user and tenant identifiers and, for a request row, a client
//! address.
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
//! about a kilobyte at most whatever the request carried. The budget counts
//! the bytes of the line as written, envelope included (about 100 more than
//! the bare entry).

use std::borrow::Cow;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use axiam_core::models::audit::CreateAuditLogEntry;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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

/// Why a row was dead-lettered: a closed set, written to the line as a short
/// snake_case name. Never an error's text, which can carry a query, an
/// identifier or a secret, and is unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadLetterReason {
    /// The request-audit channel was full when the request finished.
    ChannelFull,
    /// The request-audit channel was closed (the worker is gone).
    ChannelClosed,
    /// The datastore refused the append.
    DatastoreError,
}

impl DeadLetterReason {
    /// The name the line carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChannelFull => "channel_full",
            Self::ChannelClosed => "channel_closed",
            Self::DatastoreError => "datastore_error",
        }
    }
}

impl std::fmt::Display for DeadLetterReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a writer is given: an audit entry the datastore did not take, when the
/// event happened, and why it is here.
#[derive(Debug, Clone)]
pub struct DeadLetterRecord {
    /// When the event happened (see the module docs), not when it is written.
    pub occurred_at: DateTime<Utc>,
    /// Why the row was dead-lettered.
    pub reason: DeadLetterReason,
    /// The row to replay.
    pub entry: CreateAuditLogEntry,
}

impl DeadLetterRecord {
    /// A record of `entry`, which happened at `occurred_at`.
    pub fn new(
        entry: CreateAuditLogEntry,
        occurred_at: DateTime<Utc>,
        reason: DeadLetterReason,
    ) -> Self {
        Self {
            occurred_at,
            reason,
            entry,
        }
    }
}

/// A line as it is written: the envelope around the entry.
#[derive(Serialize)]
struct LineOut<'a> {
    occurred_at: DateTime<Utc>,
    reason: DeadLetterReason,
    entry: &'a CreateAuditLogEntry,
}

/// A line as it is read: the envelope, or the bare entry earlier versions
/// wrote. The envelope is tried first; it needs an `entry` key, which a bare
/// entry does not have.
#[derive(Deserialize)]
#[serde(untagged)]
enum LineIn {
    Enveloped {
        occurred_at: DateTime<Utc>,
        #[serde(default)]
        reason: Option<String>,
        entry: CreateAuditLogEntry,
    },
    Bare(CreateAuditLogEntry),
}

/// A dead-letter line read back by [`decode_line`].
#[derive(Debug, Clone)]
pub struct DeadLetterLine {
    /// When the event happened; `None` for a bare line from an earlier version.
    pub occurred_at: Option<DateTime<Utc>>,
    /// Why it was dead-lettered, as the line spells it (a later version may add
    /// names); `None` for a bare line.
    pub reason: Option<String>,
    /// The row to replay.
    pub entry: CreateAuditLogEntry,
}

/// One dead-letter line, without its newline. The client-sized fields are
/// bounded (see [`bound_fields`]) whoever built the entry.
pub fn encode_line(record: &DeadLetterRecord) -> serde_json::Result<String> {
    let entry = &record.entry;
    let oversized = entry.action.len() > MAX_ACTION_BYTES
        || entry
            .ip_address
            .as_ref()
            .is_some_and(|ip| ip.len() > MAX_ADDRESS_BYTES);
    let entry = if oversized {
        let mut cut = entry.clone();
        bound_fields(&mut cut);
        Cow::Owned(cut)
    } else {
        Cow::Borrowed(entry)
    };
    serde_json::to_string(&LineOut {
        occurred_at: record.occurred_at,
        reason: record.reason,
        entry: &entry,
    })
}

/// Read one line (without its newline): the envelope [`encode_line`] writes, or
/// the bare [`CreateAuditLogEntry`] that versions before #595 wrote, which has
/// neither `occurred_at` nor `reason`.
pub fn decode_line(line: &str) -> serde_json::Result<DeadLetterLine> {
    Ok(match serde_json::from_str::<LineIn>(line)? {
        LineIn::Enveloped {
            occurred_at,
            reason,
            entry,
        } => DeadLetterLine {
            occurred_at: Some(occurred_at),
            reason,
            entry,
        },
        LineIn::Bare(entry) => DeadLetterLine {
            occurred_at: None,
            reason: None,
            entry,
        },
    })
}

/// The mode a dead-letter file is created with, and tightened to: owner only.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// The options both openers use: create, append, and owner-only on Unix.
fn open_options() -> std::fs::OpenOptions {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(FILE_MODE);
    }
    options
}

/// Whether `meta` says the file is readable or writable by group or others.
/// `mode(0o600)` applies only when the file is created, so a file an earlier
/// version (or an operator) made under a 0644 umask is found this way.
#[cfg(unix)]
fn is_exposed(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o077 != 0
}

/// The permissions an exposed file is tightened to.
#[cfg(unix)]
fn owner_only() -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::Permissions::from_mode(FILE_MODE)
}

#[cfg(unix)]
fn tighten_failed(path: &Path, error: &std::io::Error) {
    tracing::warn!(
        error = %error,
        path = %path.display(),
        "audit dead-letter file is readable by group or others and could not be \
         restricted to its owner"
    );
}

/// The dead-letter file a GDPR record goes to, and its budget, as the
/// environment names them: read once, when this is built, so one record is
/// judged against one path and one budget. A deployment without
/// [`DEAD_LETTER_FILE_ENV`] has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetterTarget {
    /// The file.
    pub path: PathBuf,
    /// The whole of the budget, the GDPR records' reserve included.
    pub max_bytes: u64,
}

impl DeadLetterTarget {
    /// The target [`DEAD_LETTER_FILE_ENV`] and [`MAX_BYTES_ENV`] name, or
    /// `None` when the file is unset or empty. An invalid budget falls back to
    /// [`DEFAULT_MAX_BYTES`]: the boot refuses one ([`DeadLetterWriter::from_env`]),
    /// so a running server has none, and a record is not dropped over it.
    pub fn from_env() -> Option<Self> {
        let path = std::env::var_os(DEAD_LETTER_FILE_ENV).filter(|p| !p.is_empty())?;
        Some(Self {
            path: PathBuf::from(path),
            max_bytes: max_bytes_from_env().unwrap_or(DEFAULT_MAX_BYTES),
        })
    }
}

/// [`append_blocking`] on the runtime's blocking pool, for a caller on an async
/// task (a request handler): the file I/O, including the sync, does not hold the
/// worker. Returns when the line is written and synced.
///
/// The write runs to completion even if the caller is dropped meanwhile, and a
/// task that panicked or was cancelled is reported as an I/O error, the same as
/// a write that failed. Needs a Tokio runtime.
///
/// A failure is logged here, inside the blocking task, so the line does not
/// depend on the caller still being there to read the result (#690): it names the
/// path and the I/O error and nothing of the record. The caller therefore does
/// not log it again.
pub async fn append_off_thread(
    target: DeadLetterTarget,
    record: DeadLetterRecord,
) -> std::io::Result<()> {
    // The blocking pool's threads do not inherit this task's thread-local
    // subscriber, so the task carries the dispatcher it was called under.
    let dispatch = tracing::dispatcher::get_default(tracing::Dispatch::clone);
    tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            let result = append_blocking(&target.path, &record, target.max_bytes);
            if let Err(e) = &result {
                tracing::error!(
                    error = %e,
                    path = %target.path.display(),
                    "gdpr: failed to append audit dead-letter file"
                );
            }
            result
        })
    })
    .await
    .map_err(|e| {
        // The closure did not return: nothing logged the failure there.
        tracing::error!(
            error = %e,
            "gdpr: failed to append audit dead-letter file"
        );
        std::io::Error::other(format!("dead-letter write task failed: {e}"))
    })?
}

/// Append `record` to the file at `path` and return when it has been written and
/// synced (`sync_data`).
///
/// Opens with `append(true)`: an existing file is never truncated or rewritten.
/// A new file is created `0600`, and an existing one that group or others can
/// read is tightened to it (see the module docs). Blocks on file I/O, so not
/// for the request path: use [`append_off_thread`] there, or
/// [`DeadLetterWriter`] for a row that does not need the guarantee.
///
/// For the GDPR records: it may write into the reserve above the request rows'
/// share, up to the whole of `max_bytes`, and refuses a line that would cross
/// it (an error of kind `StorageFull`); the line counted is the envelope's, as
/// written. The check reads the file's size before
/// the write, so a batch the writer task appends at the same moment can take
/// the file past `max_bytes` by that batch.
pub fn append_blocking(
    path: &Path,
    record: &DeadLetterRecord,
    max_bytes: u64,
) -> std::io::Result<()> {
    let mut line = encode_line(record).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut file = open_options().open(path)?;
    let meta = file.metadata()?;
    #[cfg(unix)]
    if is_exposed(&meta)
        && let Err(e) = file.set_permissions(owner_only())
    {
        tighten_failed(path, &e);
    }
    let size = meta.len();
    if size + line.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            format!(
                "the audit dead-letter file holds {size} bytes and its budget is {max_bytes} \
                 ({MAX_BYTES_ENV}); replay and move it"
            ),
        ));
    }
    // One call, so the newline cannot be separated from its line.
    file.write_all(line.as_bytes())?;
    file.sync_data()
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
    Entry(DeadLetterRecord),
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

    /// Queue `record` for the file. Never blocks and never does I/O.
    pub fn submit(&self, record: DeadLetterRecord) -> Submitted {
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
        match inner.tx.try_send(Msg::Entry(record)) {
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
                Msg::Entry(record) => match encode_line(&record) {
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
        let opened = tokio::fs::OpenOptions::from(open_options())
            .open(path)
            .await?;
        #[cfg(unix)]
        if is_exposed(&opened.metadata().await?)
            && let Err(e) = opened.set_permissions(owner_only()).await
        {
            tighten_failed(path, &e);
        }
        *file = Some(opened);
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
        // The batch is on the device before it is counted as written.
        f.sync_data().await?;
    }
    Ok(Appended {
        written,
        refused: lines.len() as u64 - written,
    })
}
