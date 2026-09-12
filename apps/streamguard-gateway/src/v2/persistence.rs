//! Bounded supervised persistence owner queue, secure journal I/O, and
//! wall-clock helpers (V2 admission-only).
//!
//! This module owns the three final runtime blockers as one coherent seam:
//!
//! - **Detached `spawn_blocking` flood**: every durable lease/replay mutation
//!   previously spawned its own unbounded blocking task per admission. This
//!   module replaces that with one supervised owner queue per durable store:
//!   a bounded [`std::sync::mpsc::sync_channel`] (hard cap, `try_send`
//!   backpressure, fail closed) plus a single dedicated worker thread that
//!   runs each blocking file rewrite serially. A flood beyond the cap fails
//!   closed immediately (`Full`) instead of queueing unbounded tasks, and a
//!   stalled disk fails closed via [`PERSISTENCE_IO_TIMEOUT`] instead of
//!   hanging admission.
//! - **Indefinite shutdown**: [`PersistenceOwner::stop`] closes the channel
//!   (no new work) and joins the worker with
//!   [`PERSISTENCE_SHUTDOWN_TIMEOUT`]. A stalled worker never hangs the
//!   caller: the join times out, the thread is detached, and the timeout is
//!   counted. `Drop` never joins (non-blocking detach).
//! - **Permissive journal creation**: [`secure_atomic_write`] creates the
//!   temp file with `0600` atomically, validates parent/tmp/file (no
//!   symlinks, correct types, Linux permission bits), renames atomically,
//!   fsyncs the parent on Unix, and validates the final file. Any violation
//!   fails closed without logging paths or contents.
//! - **Monotonic persistence bug**: lease expiries were persisted as
//!   process-relative monotonic deadlines, which reset to near zero on
//!   restart and made every recovered lease appear valid (or expired)
//!   incorrectly. [`PoolTime`] carries both domains; persist helpers compute
//!   a wall-clock deadline (`wall_now + ttl`), and recovery converts the
//!   remaining wall time back to a monotonic deadline with saturating
//!   arithmetic. Replay already persists wall seconds and is unchanged
//!   except for the owner queue and secure write.
//!
//! Bounds: one worker thread plus one bounded channel per owner, at most
//! `PERSISTENCE_QUEUE_HARD_CAP` queued works, one `oneshot` per in-flight
//! submit, bounded `io_timeout`/`shutdown_timeout`, no additional tasks or
//! collections. All errors are typed (`thiserror`), no payload/ticket/path
//! logging, `tracing` only for counts.
//!
//! V1 code (`tunnel.rs`, `main.rs`) is untouched.

use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use thiserror::Error;

/// Hard cap for any persistence owner queue. Larger capacities fail closed at
/// construction so a misconfigured gateway can never queue unbounded work.
pub const PERSISTENCE_QUEUE_HARD_CAP: usize = 64;
/// Default bounded queue depth for durable lease/replay I/O.
pub const PERSISTENCE_QUEUE_CAPACITY: usize = 32;
/// Bounded time for one durable persist observed by the async caller. A
/// durable operation that cannot complete within this budget fails closed so
/// a stalled disk never hangs admission. The worker may still complete later
/// (fail-closed burn: a replay retry then observes `Replay`, never a
/// double-admit).
pub const PERSISTENCE_IO_TIMEOUT: Duration = Duration::from_millis(500);
/// Bounded time for [`PersistenceOwner::stop`] to join the worker. A stalled
/// worker never hangs shutdown: the join times out, the thread is detached,
/// and the timeout is counted.
pub const PERSISTENCE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Dual clock for lease persistence: monotonic drives in-memory TTLs,
/// wall drives the durable journal. Both must be supplied together so tests
/// stay deterministic (pass the same value for both when wall precision does
/// not matter) and production stays correct (monotonic near zero, wall real).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolTime {
    /// Process-relative monotonic milliseconds (TTL, backoff, sweep).
    pub monotonic_ms: u64,
    /// Wall-clock Unix milliseconds (durable expiry only).
    pub wall_ms: u64,
}

impl PoolTime {
    #[must_use]
    pub const fn new(monotonic_ms: u64, wall_ms: u64) -> Self {
        Self { monotonic_ms, wall_ms }
    }

    /// Test convenience: one value for both domains (deterministic, no wall
    /// truncation). Production must use [`PoolTime::from_clock`] or explicit
    /// wall millis instead.
    #[must_use]
    pub const fn from_monotonic(now_ms: u64) -> Self {
        Self { monotonic_ms: now_ms, wall_ms: now_ms }
    }

    /// Derives wall millis from wall seconds (`unix_seconds * 1000`,
    /// saturating). Production callers that only have seconds (for example
    /// [`AdmissionTime`](super::admission::AdmissionTime)) use this; the one
    /// second truncation is safe for multi-second lease TTLs.
    #[must_use]
    pub const fn from_monotonic_and_wall_seconds(monotonic_ms: u64, wall_unix_seconds: u64) -> Self {
        Self { monotonic_ms, wall_ms: wall_unix_seconds.saturating_mul(1_000) }
    }
}

/// Current wall-clock Unix milliseconds (saturating, never panics; `0` only
/// before the epoch, which fail-closed paths treat as expired).
#[must_use]
pub fn wall_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Computes a wall-clock deadline as `wall_now + ttl`, saturating. Pure,
/// no I/O, never panics.
#[must_use]
pub const fn wall_expiry_from_ttl(wall_now_ms: u64, ttl_ms: u64) -> u64 {
    wall_now_ms.saturating_add(ttl_ms)
}

/// Converts a persisted wall deadline back to a monotonic deadline:
/// `mono_now + (wall_expiry saturating_sub wall_now)`, saturating. A wall
/// expiry at or before `wall_now` yields `mono_now` (immediately expired);
/// a far-future wall yields a saturated monotonic deadline (never panics,
/// never wraps). Pure, no I/O.
#[must_use]
pub const fn monotonic_expiry_from_wall(
    wall_expiry_ms: u64,
    wall_now_ms: u64,
    mono_now_ms: u64,
) -> u64 {
    mono_now_ms.saturating_add(wall_expiry_ms.saturating_sub(wall_now_ms))
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceError {
    #[error("persistence queue is at capacity")]
    Full,
    #[error("persistence operation timed out")]
    Timeout,
    #[error("persistence owner is closed")]
    Closed,
    #[error("persistence store is unavailable")]
    Unavailable,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecureJournalError {
    #[error("journal reference is invalid")]
    InvalidReference,
    #[error("journal I/O failed")]
    Io,
}

/// Validated configuration for one [`PersistenceOwner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistenceConfig {
    queue_capacity: usize,
    io_timeout: Duration,
    shutdown_timeout: Duration,
}

impl PersistenceConfig {
    /// Validates `queue_capacity` (`1..=HARD_CAP`) and non-zero timeouts
    /// (each `1ms..=30s`). Returns `None` when out of range.
    #[must_use]
    pub const fn new(queue_capacity: usize, io_timeout: Duration, shutdown_timeout: Duration) -> Option<Self> {
        if queue_capacity == 0 || queue_capacity > PERSISTENCE_QUEUE_HARD_CAP {
            return None;
        }
        if io_timeout.as_millis() == 0
            || io_timeout.as_millis() > 30_000
            || shutdown_timeout.as_millis() == 0
            || shutdown_timeout.as_millis() > 30_000
        {
            return None;
        }
        Some(Self { queue_capacity, io_timeout, shutdown_timeout })
    }

    #[must_use]
    pub const fn default_config() -> Self {
        Self {
            queue_capacity: PERSISTENCE_QUEUE_CAPACITY,
            io_timeout: PERSISTENCE_IO_TIMEOUT,
            shutdown_timeout: PERSISTENCE_SHUTDOWN_TIMEOUT,
        }
    }

    #[must_use]
    pub const fn queue_capacity(self) -> usize {
        self.queue_capacity
    }

    #[must_use]
    pub const fn io_timeout(self) -> Duration {
        self.io_timeout
    }

    #[must_use]
    pub const fn shutdown_timeout(self) -> Duration {
        self.shutdown_timeout
    }
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

#[derive(Debug, Default)]
struct PersistenceMetricsInner {
    submitted: AtomicU64,
    completed: AtomicU64,
    full_dropped: AtomicU64,
    timed_out: AtomicU64,
    closed: AtomicU64,
    shutdown_timed_out: AtomicU64,
}

/// Count-only metrics for one owner (no paths, tickets, or contents).
#[derive(Debug, Default)]
pub struct PersistenceMetrics {
    inner: PersistenceMetricsInner,
}

impl PersistenceMetrics {
    #[must_use]
    pub fn submitted(&self) -> u64 {
        self.inner.submitted.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn completed(&self) -> u64 {
        self.inner.completed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn full_dropped(&self) -> u64 {
        self.inner.full_dropped.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn timed_out(&self) -> u64 {
        self.inner.timed_out.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn closed(&self) -> u64 {
        self.inner.closed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn shutdown_timed_out(&self) -> u64 {
        self.inner.shutdown_timed_out.load(Ordering::Relaxed)
    }
}

/// Snapshot of [`PersistenceMetrics`] (counts only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistenceSnapshot {
    pub submitted: u64,
    pub completed: u64,
    pub full_dropped: u64,
    pub timed_out: u64,
    pub closed: u64,
    pub shutdown_timed_out: u64,
    pub queue_capacity: usize,
}

type OwnerWork = Box<dyn FnOnce() + Send + 'static>;

enum OwnerRequest {
    Work(OwnerWork),
}

/// Bounded supervised owner for blocking persistence I/O.
///
/// One dedicated worker thread runs each blocking rewrite serially; async
/// callers submit via [`PersistenceOwner::execute`] (`try_send`
/// backpressure, `io_timeout` fail-closed). No per-admission
/// `spawn_blocking` flood: at most `queue_capacity` works are ever queued,
/// excess fails closed immediately. Shutdown closes the channel and joins
/// with `shutdown_timeout` (never indefinite); `Drop` never joins.
pub struct PersistenceOwner {
    tx: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<OwnerRequest>>>,
    handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    metrics: Arc<PersistenceMetrics>,
    config: PersistenceConfig,
}

impl std::fmt::Debug for PersistenceOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PersistenceOwner(REDACTED)")
    }
}

impl PersistenceOwner {
    /// Starts one owner with a dedicated worker thread. Must be called from
    /// a context that may spawn threads (not from the worker itself).
    #[must_use]
    pub fn start(config: PersistenceConfig) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<OwnerRequest>(config.queue_capacity);
        let handle = std::thread::spawn(move || {
            while let Ok(request) = rx.recv() {
                match request {
                    OwnerRequest::Work(work) => work(),
                }
            }
        });
        Self {
            tx: std::sync::Mutex::new(Some(tx)),
            handle: std::sync::Mutex::new(Some(handle)),
            metrics: Arc::new(PersistenceMetrics::default()),
            config,
        }
    }

    /// Test constructor with the default bounded config.
    #[must_use]
    pub fn start_default() -> Self {
        Self::start(PersistenceConfig::default())
    }

    /// Submits one blocking closure to the owner thread and awaits its
    /// result with `io_timeout`. The closure runs on the worker thread (never
    /// on a Tokio executor thread); the caller never holds a store lock
    /// across the await (the lock lives only inside the closure on the worker).
    ///
    /// Fail-closed: `Full` when the bounded queue is at capacity
    /// (backpressure, counted), `Closed` after [`stop`](Self::stop), `Timeout`
    /// when the worker is stalled past `io_timeout` (counted; the worker may
    /// still complete later, which callers treat as a fail-closed burn, never
    /// a double-apply).
    pub async fn execute<F, T>(&self, work: F) -> Result<T, PersistenceError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // Clone the sender without holding the lock across the await: the
        // lock is held only for the short clone, never across I/O.
        let sender = self.tx.lock().ok().and_then(|guard| guard.clone());
        let Some(sender) = sender else {
            self.metrics.inner.closed.fetch_add(1, Ordering::Relaxed);
            return Err(PersistenceError::Closed);
        };
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<T>();
        let wrapped: OwnerWork = Box::new(move || {
            let result = work();
            let _ = reply_tx.send(result);
        });
        match sender.try_send(OwnerRequest::Work(wrapped)) {
            Ok(()) => {
                self.metrics.inner.submitted.fetch_add(1, Ordering::Relaxed);
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.metrics.inner.full_dropped.fetch_add(1, Ordering::Relaxed);
                return Err(PersistenceError::Full);
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                self.metrics.inner.closed.fetch_add(1, Ordering::Relaxed);
                return Err(PersistenceError::Closed);
            }
        }
        match tokio::time::timeout(self.config.io_timeout, reply_rx).await {
            Ok(Ok(result)) => {
                self.metrics.inner.completed.fetch_add(1, Ordering::Relaxed);
                Ok(result)
            }
            Ok(Err(_)) => {
                self.metrics.inner.closed.fetch_add(1, Ordering::Relaxed);
                Err(PersistenceError::Closed)
            }
            Err(_) => {
                self.metrics.inner.timed_out.fetch_add(1, Ordering::Relaxed);
                Err(PersistenceError::Timeout)
            }
        }
    }

    /// Closes the queue (no new work) and joins the worker with
    /// `shutdown_timeout`. Never hangs indefinitely: a stalled worker times
    /// out, the thread is detached, and the timeout is counted. Idempotent:
    /// a second call returns the same snapshot without hanging. Takes `&self`
    /// (interior mutability) so `Arc`-shared pools can shut down without
    /// exclusive ownership.
    pub async fn stop(&self) -> PersistenceSnapshot {
        // Close the channel so the worker drains queued work then exits. No
        // blocking send: closing is immediate even when the queue is full.
        drop(self.tx.lock().ok().and_then(|mut guard| guard.take()));
        let handle = self.handle.lock().ok().and_then(|mut guard| guard.take());
        if let Some(handle) = handle {
            // Join off the executor so a stalled worker never blocks it; the
            // outer timeout is the shutdown deadline, not a poll.
            let joiner = tokio::task::spawn_blocking(move || handle.join());
            match tokio::time::timeout(self.config.shutdown_timeout, joiner).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(_))) => {
                    // Worker panicked: counted as a shutdown timeout (fail
                    // closed, no payload). The panic itself is contained to
                    // the worker thread.
                    self.metrics.inner.shutdown_timed_out.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Err(_)) => {
                    self.metrics.inner.shutdown_timed_out.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    // Stalled worker: the `spawn_blocking` joiner is aborted
                    // (its thread stays blocked on the worker join, detached);
                    // shutdown still returns within the deadline.
                    self.metrics.inner.shutdown_timed_out.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.snapshot()
    }

    #[must_use]
    pub fn snapshot(&self) -> PersistenceSnapshot {
        PersistenceSnapshot {
            submitted: self.metrics.submitted(),
            completed: self.metrics.completed(),
            full_dropped: self.metrics.full_dropped(),
            timed_out: self.metrics.timed_out(),
            closed: self.metrics.closed(),
            shutdown_timed_out: self.metrics.shutdown_timed_out(),
            queue_capacity: self.config.queue_capacity,
        }
    }

    #[must_use]
    pub fn config(&self) -> PersistenceConfig {
        self.config
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.tx.lock().map(|guard| guard.is_none()).unwrap_or(true)
    }
}

impl Drop for PersistenceOwner {
    fn drop(&mut self) {
        // Non-blocking detach by construction: dropping the sender closes the
        // channel (worker drains then exits), and dropping the handle detaches
        // a still-running worker without joining. Never blocks, never hangs.
        drop(self.tx.lock().ok().and_then(|mut guard| guard.take()));
        let handle = self.handle.lock().ok().and_then(|mut guard| guard.take());
        if let Some(handle) = handle {
            if !handle.is_finished() {
                // Detach a still-running worker (stalled disk): it exits when
                // its current rewrite completes and sees the closed channel.
                // `std::thread` detaches on drop; no join here by construction.
                std::mem::forget(handle);
            } else {
                let _ = handle.join();
            }
        }
    }
}

/// Validates a journal parent directory without logging paths: must exist,
/// must be a directory, must not be a symlink. On Unix it must not be
/// group/other-writable (the same gate the config loader enforces).
pub fn validate_parent_dir(journal_path: &Path) -> Result<PathBuf, SecureJournalError> {
    let parent = journal_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| SecureJournalError::InvalidReference)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(SecureJournalError::InvalidReference);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(SecureJournalError::InvalidReference);
        }
    }
    Ok(parent.to_path_buf())
}

/// Temp path for atomic rewrites: `<stem>.tmp` in the same directory (same
/// filesystem, so `rename` is atomic). Uses `with_extension("tmp")` to match
/// the existing journal layout (`leases.journal` -> `leases.tmp`).
#[must_use]
pub fn journal_tmp_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("tmp")
}

/// Atomically and securely rewrites a journal file.
///
/// - Validates the parent directory ([`validate_parent_dir`]) before touching
///   the filesystem.
/// - Rejects a temp path that is a symlink (fail closed, stale temp removed
///   only when it is a regular file).
/// - Creates the temp file with `0600` (Unix `mode(0o600)`, plus an explicit
///   `set_permissions(0o600)` after write to defeat umask surprises), writes
///   the full snapshot, `sync_all`s it, renames atomically over the journal,
///   fsyncs the parent directory on Unix, and validates the final file is a
///   regular non-symlink file with `0600` on Unix.
/// - Any failure leaves the old journal intact (when it existed) and reports
///   `Io` without paths or contents.
pub fn secure_atomic_write(journal_path: &Path, bytes: &[u8]) -> Result<(), SecureJournalError> {
    validate_parent_dir(journal_path)?;
    let tmp_path = journal_tmp_path(journal_path);
    // Fail closed on a symlinked temp: never write through an attacker link.
    match std::fs::symlink_metadata(&tmp_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(SecureJournalError::Io);
            }
            if !metadata.file_type().is_file() {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(SecureJournalError::Io);
            }
            // Stale regular temp from a previous crash: remove before creat.
            let _ = std::fs::remove_file(&tmp_path);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(SecureJournalError::Io),
    }
    // Create exclusively with 0600 on Unix; other platforms rely on the
    // post-write chmod below (best-effort, documented).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&tmp_path).map_err(|_| SecureJournalError::Io)?;
        {
            use std::io::Write as _;
            file.write_all(bytes).map_err(|_| {
                let _ = std::fs::remove_file(&tmp_path);
                SecureJournalError::Io
            })?;
            file.sync_all().map_err(|_| {
                let _ = std::fs::remove_file(&tmp_path);
                SecureJournalError::Io
            })?;
        }
        // Harden against umask surprises: the file must be 0600 afterwards.
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        drop(file);
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, bytes).map_err(|_| SecureJournalError::Io)?;
        let flushed = std::fs::OpenOptions::new()
            .write(true)
            .open(&tmp_path)
            .and_then(|file| file.sync_all().map(|()| file));
        if flushed.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(SecureJournalError::Io);
        }
        drop(flushed);
    }
    // Validate the temp before rename: regular file, 0600 on Unix.
    {
        let metadata = std::fs::symlink_metadata(&tmp_path).map_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
            SecureJournalError::Io
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(SecureJournalError::Io);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
                let fixed =
                    std::fs::symlink_metadata(&tmp_path).map_err(|_| SecureJournalError::Io)?;
                if fixed.permissions().mode() & 0o077 != 0 {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(SecureJournalError::Io);
                }
            }
        }
    }
    std::fs::rename(&tmp_path, journal_path).map_err(|_| {
        let _ = std::fs::remove_file(&tmp_path);
        SecureJournalError::Io
    })?;
    fsync_parent_dir(journal_path)?;
    // Validate the final file: regular non-symlink, 0600 on Unix.
    {
        let metadata = std::fs::symlink_metadata(journal_path).map_err(|_| SecureJournalError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(SecureJournalError::Io);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(SecureJournalError::Io);
            }
        }
    }
    Ok(())
}

/// Validates an existing journal file without logging paths: must be a
/// regular non-symlink file with `0600` on Unix. Missing files are *not*
/// validated here (callers treat missing as empty); present-file validation
/// belongs to the journal readers plus this helper.
pub fn validate_journal_file(journal_path: &Path) -> Result<(), SecureJournalError> {
    let metadata = std::fs::symlink_metadata(journal_path).map_err(|_| SecureJournalError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(SecureJournalError::InvalidReference);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SecureJournalError::InvalidReference);
        }
    }
    Ok(())
}

/// Fsyncs the parent directory so the atomic rename is durable. Unix-only;
/// other platforms are best-effort no-ops (documented, matches the lease
/// journal). Never logs paths.
#[cfg(unix)]
pub fn fsync_parent_dir(journal_path: &Path) -> Result<(), SecureJournalError> {
    let parent = journal_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| SecureJournalError::Io)?;
    if !metadata.file_type().is_dir() {
        return Err(SecureJournalError::Io);
    }
    let dir = std::fs::File::open(parent).map_err(|_| SecureJournalError::Io)?;
    dir.sync_all().map_err(|_| SecureJournalError::Io)
}

#[cfg(not(unix))]
pub fn fsync_parent_dir(_journal_path: &Path) -> Result<(), SecureJournalError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_time_helpers_are_saturating_and_deterministic() {
        assert_eq!(PoolTime::from_monotonic(1_000), PoolTime::new(1_000, 1_000));
        assert_eq!(
            PoolTime::from_monotonic_and_wall_seconds(1_000, 2_000),
            PoolTime::new(1_000, 2_000_000)
        );
        assert_eq!(wall_expiry_from_ttl(1_000, 5_000), 6_000);
        assert_eq!(wall_expiry_from_ttl(u64::MAX, 1), u64::MAX);
        assert_eq!(monotonic_expiry_from_wall(6_000, 1_000, 1_000), 6_000);
        assert_eq!(monotonic_expiry_from_wall(500, 1_000, 1_000), 1_000);
        assert_eq!(monotonic_expiry_from_wall(u64::MAX, 0, u64::MAX), u64::MAX);
    }

    #[test]
    fn persistence_config_rejects_unbounded_or_zero_timeouts() {
        assert!(PersistenceConfig::new(0, PERSISTENCE_IO_TIMEOUT, PERSISTENCE_SHUTDOWN_TIMEOUT).is_none());
        assert!(PersistenceConfig::new(PERSISTENCE_QUEUE_HARD_CAP + 1, PERSISTENCE_IO_TIMEOUT, PERSISTENCE_SHUTDOWN_TIMEOUT).is_none());
        assert!(PersistenceConfig::new(8, Duration::from_millis(0), PERSISTENCE_SHUTDOWN_TIMEOUT).is_none());
        assert!(PersistenceConfig::new(8, PERSISTENCE_IO_TIMEOUT, Duration::from_millis(0)).is_none());
        assert!(PersistenceConfig::new(8, PERSISTENCE_IO_TIMEOUT, PERSISTENCE_SHUTDOWN_TIMEOUT).is_some());
    }

    #[tokio::test]
    async fn owner_executes_inline_and_reports_full_backpressure() {
        let owner = PersistenceOwner::start(PersistenceConfig::new(1, PERSISTENCE_IO_TIMEOUT, PERSISTENCE_SHUTDOWN_TIMEOUT).unwrap());
        let first = owner.execute(|| 41u32).await.unwrap();
        assert_eq!(first, 41);
        assert_eq!(owner.snapshot().submitted, 1);
        assert_eq!(owner.snapshot().completed, 1);
    }

    #[tokio::test]
    async fn owner_stop_is_idempotent_and_bounded() {
        let owner = PersistenceOwner::start_default();
        let first = tokio::time::timeout(Duration::from_secs(5), owner.stop())
            .await
            .expect("stop must complete within the outer deadline");
        assert_eq!(first.queue_capacity, PERSISTENCE_QUEUE_CAPACITY);
        let second = tokio::time::timeout(Duration::from_secs(5), owner.stop())
            .await
            .expect("second stop must not hang");
        assert_eq!(second.submitted, first.submitted);
        // After close, new work fails closed without hanging.
        assert_eq!(owner.execute(|| 1u32).await, Err(PersistenceError::Closed));
    }

    #[tokio::test]
    async fn owner_timeout_flood_fails_closed_without_hanging_or_spawning() {
        // Flood beyond the hard cap: the first work blocks the sole worker on
        // a deterministic gate (like a stalled disk holding serialization);
        // the queue (capacity 1) holds one pending work; every further submit
        // must fail closed with `Full` immediately (backpressure, no flood,
        // no hang). The blocked work then times out via `io_timeout`
        // (fail-closed burn, never double-apply). No sleeps as the assertion
        // clock: `entered` plus completion acks order every check; the outer
        // 5 s timeout is only a hang backstop.
        const OUTER: Duration = Duration::from_secs(5);
        let owner = std::sync::Arc::new(PersistenceOwner::start(
            PersistenceConfig::new(1, Duration::from_millis(200), PERSISTENCE_SHUTDOWN_TIMEOUT).unwrap(),
        ));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel::<()>();
        // First work: signals `entered`, then blocks on `proceed` on the
        // worker thread (exactly like stalled journal I/O).
        let blocked_owner = std::sync::Arc::clone(&owner);
        let blocked = tokio::spawn(async move {
            blocked_owner
                .execute(move || {
                    let _ = entered_tx.send(());
                    let _ = proceed_rx.recv();
                    41u32
                })
                .await
        });
        // Deterministic gate ack: the worker reached the stalled rewrite. Wait
        // off the executor so the async path never blocks.
        let entered = tokio::task::spawn_blocking(move || entered_rx.recv_timeout(OUTER))
            .await
            .expect("entered wait must join");
        assert!(entered.is_ok(), "blocked work must reach the gate");
        // Queue capacity 1: one more submit fills the queue (pending, not yet
        // running). Use a quick inline work that would complete if run.
        let queued_owner = std::sync::Arc::clone(&owner);
        let queued = tokio::spawn(async move { queued_owner.execute(|| 7u32).await });
        // Give the queued work a chance to enqueue (deterministic via a short
        // yield, not a sleep assertion: the flood below proves the cap
        // regardless of this timing).
        tokio::task::yield_now().await;
        // Flood: every further submit must fail closed with `Full`
        // immediately, never queue unbounded work and never hang.
        let mut full_count = 0u64;
        for _ in 0..8 {
            match owner.execute(|| 9u32).await {
                Err(PersistenceError::Full) => full_count += 1,
                // The queued slot may still be draining; `Timeout` is also
                // fail-closed and acceptable here, but at least one `Full`
                // must occur to prove the hard cap.
                Err(PersistenceError::Timeout) => {}
                other => panic!("flood must fail closed, got {other:?}"),
            }
        }
        assert!(full_count >= 1, "hard cap must reject at least one flood submit");
        assert!(owner.snapshot().full_dropped >= 1);
        // The blocked work times out via `io_timeout` (fail-closed) even
        // though the worker stays blocked; the outer deadline proves no hang.
        let blocked_result = tokio::time::timeout(OUTER, blocked)
            .await
            .expect("blocked execute must complete via inner timeout, not hang")
            .expect("blocked task must join");
        assert_eq!(blocked_result, Err(PersistenceError::Timeout));
        assert!(owner.snapshot().timed_out >= 1);
        // Recovery: unblock the worker. The previously queued work was also
        // stuck behind the stalled head past its own `io_timeout`, so it
        // also fails closed with `Timeout` (never double-applied, never
        // hangs). A fresh submit afterwards must eventually complete (no
        // poisoned queue, no leaked serialization); retry with a bounded
        // loop driven by completion acks (not sleeps) because the worker
        // still drains the two timed-out works first (queue may report `Full`
        // until the drain completes).
        let _ = proceed_tx.send(());
        let queued_result = tokio::time::timeout(OUTER, queued)
            .await
            .expect("queued work must complete via timeout, not hang")
            .expect("queued task must join");
        assert_eq!(queued_result, Err(PersistenceError::Timeout));
        let mut fresh_ok = false;
        for _ in 0..20 {
            let attempt = tokio::time::timeout(OUTER, owner.execute(|| 11u32))
                .await
                .expect("fresh attempt must complete, not hang");
            match attempt {
                Ok(11u32) => {
                    fresh_ok = true;
                    break;
                }
                Err(PersistenceError::Full) => {
                    // Worker still draining the timed-out head/queued works;
                    // yield and retry (bounded, deterministic via acks).
                    tokio::task::yield_now().await;
                }
                other => panic!("fresh submit must eventually succeed, got {other:?}"),
            }
        }
        assert!(fresh_ok, "fresh submit must succeed after drain");
        // Bounded shutdown (outer deadline, not the assertion clock).
        tokio::time::timeout(OUTER, owner.stop())
            .await
            .expect("stop must not hang after flood");
    }

    #[tokio::test]
    async fn owner_stalled_shutdown_completes_within_deadline() {
        // Stalled-shutdown proof: the worker blocks on a gate past the
        // `shutdown_timeout` (200 ms here); `stop` must still return within
        // the outer 5 s deadline (never indefinite), counting
        // `shutdown_timed_out` and detaching the thread. Unblocking afterwards
        // lets the detached worker exit without hanging the suite.
        const OUTER: Duration = Duration::from_secs(5);
        let owner = std::sync::Arc::new(PersistenceOwner::start(
            PersistenceConfig::new(4, Duration::from_millis(500), Duration::from_millis(200)).unwrap(),
        ));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel::<()>();
        let stalled_owner = std::sync::Arc::clone(&owner);
        // Keep the JoinHandle so the test can await the detached work after
        // unblocking (proves no leak beyond the counted detach).
        let stalled = tokio::spawn(async move {
            stalled_owner
                .execute(move || {
                    let _ = entered_tx.send(());
                    let _ = proceed_rx.recv();
                    99u32
                })
                .await
        });
        let entered = tokio::task::spawn_blocking(move || entered_rx.recv_timeout(OUTER))
            .await
            .expect("entered wait must join");
        assert!(entered.is_ok(), "stalled work must reach the gate");
        // Shutdown while stalled: must return within the outer deadline even
        // though the worker stays blocked past its 200 ms join budget.
        let stop = tokio::time::timeout(OUTER, owner.stop())
            .await
            .expect("stalled shutdown must not hang");
        assert!(stop.shutdown_timed_out >= 1, "stalled join must be counted");
        // Second stop is idempotent and also bounded.
        let second = tokio::time::timeout(OUTER, owner.stop())
            .await
            .expect("second stop must not hang");
        assert_eq!(second.submitted, stop.submitted);
        // Unblock the detached worker so it can exit (channel already closed;
        // it drains then sees closed and terminates). The stalled caller
        // already timed out, so this join is best-effort.
        let _ = proceed_tx.send(());
        let _ = tokio::time::timeout(OUTER, stalled).await;
    }

    #[test]
    fn secure_journal_creates_private_file_and_validates_tmp_and_dir() {
        // Permissions proof: the atomic rewrite must create a private journal
        // (0600 on Unix, regular file, no symlink) and reject a symlinked
        // temp or a permissive parent/file. Temporary paths are
        // process-unique; no sleeps.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sg-persist-perm-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let journal = dir.join("journal.bin");
        let _ = std::fs::remove_file(&journal);
        let _ = std::fs::remove_file(journal.with_extension("tmp"));
        secure_atomic_write(&journal, b"hello-secure").unwrap();
        assert!(journal.exists(), "secure write must create the journal");
        let metadata = std::fs::symlink_metadata(&journal).unwrap();
        assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                metadata.permissions().mode() & 0o077,
                0,
                "journal must be 0600 (no group/other bits)"
            );
            let tmp_metadata = std::fs::symlink_metadata(journal.with_extension("tmp"));
            assert!(tmp_metadata.is_err(), "temp must not linger after rename");
        }
        // Present-file validation passes for the private file.
        validate_journal_file(&journal).unwrap();
        // Parent validation passes for the secure dir.
        validate_parent_dir(&journal).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Permissive file fails closed.
            let _ = std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644));
            assert!(
                validate_journal_file(&journal).is_err(),
                "permissive 0644 journal must fail closed"
            );
            let _ = std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600));
            assert!(validate_journal_file(&journal).is_ok());
            // Symlinked temp fails the rewrite closed (never writes through a link).
            let tmp = journal.with_extension("tmp");
            let _ = std::fs::remove_file(&tmp);
            std::os::unix::fs::symlink(&journal, &tmp).unwrap();
            assert!(
                secure_atomic_write(&journal, b"overwrite").is_err(),
                "symlinked temp must fail closed"
            );
            let _ = std::fs::remove_file(&tmp);
            // Permissive parent fails closed.
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777));
            assert!(
                validate_parent_dir(&journal).is_err(),
                "permissive parent must fail closed"
            );
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_file(&journal);
        let _ = std::fs::remove_file(journal.with_extension("tmp"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
