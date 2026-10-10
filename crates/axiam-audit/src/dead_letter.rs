//! The audit dead-letter file: where an audit row goes when the datastore did
//! not take it (T19.27, T-108).
//!
//! One file, named by `AXIAM__GDPR_AUDIT_DLQ_FILE`, append-only, one
//! [`CreateAuditLogEntry`] as JSON per line. That line is the replayable form:
//! an operator (or a later replay job) reads each line back into a
//! `CreateAuditLogEntry` and appends it once the datastore is healthy. The GDPR
//! erasure record's dead letter (`write_erasure_audit_with_dlq`) and the
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

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axiam_core::models::audit::CreateAuditLogEntry;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{mpsc, oneshot};

/// Environment variable naming the dead-letter file. Intended to point at a
/// mounted volume so the file survives a restart. Unset (or empty) means no file
/// is written and a lost row is counted and logged only.
pub const DEAD_LETTER_FILE_ENV: &str = "AXIAM__GDPR_AUDIT_DLQ_FILE";

/// Rows the writer task may hold before [`DeadLetterWriter::submit`] refuses
/// one. Bounded so a slow volume cannot grow memory without limit while the
/// datastore is also down; a row refused here is counted as unrecoverable.
const QUEUE_CAPACITY: usize = 1024;

/// Rows written per file write, so a burst costs one syscall rather than one
/// per row.
const BATCH: usize = 64;

/// One dead-letter line, without its newline.
pub fn encode_line(entry: &CreateAuditLogEntry) -> serde_json::Result<String> {
    serde_json::to_string(entry)
}

/// Append `entry` to the file at `path` and return when it has been written.
///
/// Opens with `append(true)`: an existing file is never truncated or rewritten.
/// Blocks on file I/O, so not for the request path — see [`DeadLetterWriter`].
pub fn append_blocking(path: &Path, entry: &CreateAuditLogEntry) -> std::io::Result<()> {
    let line = encode_line(entry).map_err(std::io::Error::other)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")
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
}

enum Msg {
    Entry(CreateAuditLogEntry),
    Flush(oneshot::Sender<()>),
}

#[derive(Default)]
struct Counts {
    written: AtomicU64,
    lost: AtomicU64,
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

    /// The writer [`DEAD_LETTER_FILE_ENV`] names, or a disabled one when it is
    /// unset or empty. Spawns the writer task, so call it inside a runtime.
    pub fn from_env() -> Self {
        match std::env::var_os(DEAD_LETTER_FILE_ENV) {
            Some(path) if !path.is_empty() => Self::spawn(PathBuf::from(path)),
            _ => Self::disabled(),
        }
    }

    /// Write to `path`, creating it when absent and appending when present.
    /// Spawns the writer task, so call it inside a runtime.
    pub fn spawn(path: impl Into<PathBuf>) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let counts = Arc::new(Counts::default());
        tokio::spawn(write_task(path.into(), rx, Arc::clone(&counts)));
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
    /// want of queue room, or queued and then not written (the file could not
    /// be opened or written).
    pub fn lost(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |i| i.counts.lost.load(Ordering::Relaxed))
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

async fn write_task(path: PathBuf, mut rx: mpsc::Receiver<Msg>, counts: Arc<Counts>) {
    let mut file: Option<tokio::fs::File> = None;
    // Logged on the way into failure, not per batch: a volume that is gone
    // would otherwise add a line per burst to a log that is already busy.
    let mut failing = false;
    while let Some(first) = rx.recv().await {
        let mut lines = String::new();
        let mut rows: u64 = 0;
        let mut flushes = Vec::new();
        let mut next = Some(first);
        while let Some(msg) = next.take() {
            match msg {
                Msg::Entry(entry) => match encode_line(&entry) {
                    Ok(line) => {
                        lines.push_str(&line);
                        lines.push('\n');
                        rows += 1;
                    }
                    Err(e) => {
                        counts.lost.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(error = %e, "audit dead-letter record could not be encoded");
                    }
                },
                Msg::Flush(done) => flushes.push(done),
            }
            if rows < BATCH as u64 {
                next = rx.try_recv().ok();
            }
        }
        if rows > 0 {
            match append(&path, &mut file, lines.as_bytes()).await {
                Ok(()) => {
                    counts.written.fetch_add(rows, Ordering::Relaxed);
                    failing = false;
                }
                Err(e) => {
                    // A handle that failed may be a dead one; reopen next time.
                    file = None;
                    counts.lost.fetch_add(rows, Ordering::Relaxed);
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

async fn append(
    path: &Path,
    file: &mut Option<tokio::fs::File>,
    bytes: &[u8],
) -> std::io::Result<()> {
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
    f.write_all(bytes).await?;
    f.flush().await
}
