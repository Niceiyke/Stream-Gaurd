//! Admission-only V2 gateway runtime (no TUN, no NAT, no V1).
//!
//! This is the approved admission-only entrypoint's owning runtime. It binds
//! exactly the V2 admission plane and nothing else:
//!
//! - [`V2GatewaySetup`] (shared address pool, authoritative session map, one
//!   clock domain, both supervised sweeps).
//! - [`AdmissionHandler`](super::admission::AdmissionHandler) with the
//!   durable single-gateway redemption journal and the bounded handshake
//!   limiter.
//! - [`V2AdmissionListener`](super::listener::V2AdmissionListener) with mTLS,
//!   bounded control deadlines, and the atomic reserve/commit/lease ordering.
//! - One bounded [`JoinSet`](tokio::task::JoinSet) for control tasks plus
//!   explicit cancellation and endpoint ownership.
//!
//! Admission-only label: there is no TUN device, no flow table, no NAT, no
//! `GatewayQuic`, no V1 `server_tls`, and no platform networking in this
//! module. Adding any of those is a compile error by construction (no such
//! import exists here).
//!
//! Bounds: at most `maximum_connections` concurrent control tasks, at most
//! `maximum_control_messages_per_connection` control requests per admitted
//! connection, bounded control frames and deadlines from the configuration,
//! bounded session/pool/replay maps from the configuration. Shutdown joins
//! sweeps and tasks, closes every session (releasing leases via cleanup),
//! and closes the endpoint. Startup recovery sweeps expired state and fails
//! closed on corrupt journals or unavailable state.

use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use sg_auth::device::{DeviceCredentialError, VerifiedPeerDeviceIdentityExtractor, validate_verified_peer_chain};
use sg_auth::ticket::TicketVerifier;
use sg_core::v2::DeviceId;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::address_pool::{AddressPool, AddressPoolMode};
use super::admission::{AdmissionHandler, AdmissionTime, HandshakeAdmissionLimiter, ReplayCache};
use super::config::{V2GatewayConfig, V2GatewayConfigError};
use super::listener::{SessionAdmitTemplate, V2AdmissionListener, V2AdmissionListenerSetup, V2AdmissionTls};
use super::session_manager::{Clock, MonotonicClock, V2SessionManager};
use super::setup::{V2GatewaySetup, V2GatewaySetupMetrics};

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum V2GatewayRuntimeError {
    #[error("V2 gateway configuration is invalid")]
    InvalidConfiguration,
    #[error("V2 gateway filesystem reference is invalid")]
    FilesystemRef,
    #[error("V2 gateway must not run with a shared secret environment value")]
    SharedSecretPresent,
    #[error("V2 gateway lease mode must be self-hosted")]
    LeaseModeRejected,
    #[error("V2 gateway ticket redemption requires single-gateway scope")]
    RedemptionScopeRejected,
    #[error("V2 gateway ticket redemption scope is invalid")]
    RedemptionScopeInvalid,
    #[error("V2 gateway configuration cannot be read")]
    Io,
    #[error("V2 gateway configuration is malformed")]
    Malformed,
    #[error("V2 gateway admission state is unavailable")]
    Unavailable,
    #[error("V2 gateway ticket redemption journal is unavailable")]
    ReplayStore,
    #[error("V2 gateway listener is unavailable")]
    Listener,
}
impl From<V2GatewayConfigError> for V2GatewayRuntimeError {
    fn from(error: V2GatewayConfigError) -> Self {
        match error {
            V2GatewayConfigError::Io => Self::Io,
            V2GatewayConfigError::Malformed => Self::Malformed,
            V2GatewayConfigError::InvalidConfiguration => Self::InvalidConfiguration,
            V2GatewayConfigError::FilesystemRef => Self::FilesystemRef,
            V2GatewayConfigError::SharedSecretPresent => Self::SharedSecretPresent,
            V2GatewayConfigError::LeaseModeRejected => Self::LeaseModeRejected,
            V2GatewayConfigError::RedemptionScopeRejected => Self::RedemptionScopeRejected,
            V2GatewayConfigError::RedemptionScopeInvalid => Self::RedemptionScopeInvalid,
        }
    }
}

/// Device identity extractor binding the verified mTLS leaf certificate to a
/// full-width [`DeviceId`] via its SHA-256 hash.
///
/// Production enrollment should map certificates to enrolled device records;
/// the admission-only entrypoint binds the ticket's device claim to the exact
/// verified leaf so a ticket minted for one device can never authorize
/// another. The hash is deterministic and opaque; it never logs certificate
/// bytes.
#[derive(Debug, Default)]
struct CertHashDeviceExtractor;

impl VerifiedPeerDeviceIdentityExtractor for CertHashDeviceExtractor {
    fn extract(
        &self,
        verified_chain: &[rustls::pki_types::CertificateDer<'_>],
    ) -> Result<DeviceId, DeviceCredentialError> {
        validate_verified_peer_chain(verified_chain)?;
        let leaf = verified_chain.first().ok_or(DeviceCredentialError::PeerIdentityUnavailable)?;
        let digest = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest.as_ref()[0..16]);
        if id.iter().all(|byte| *byte == 0) {
            return Err(DeviceCredentialError::PeerIdentityUnavailable);
        }
        Ok(DeviceId::from_bytes(id))
    }
}

#[derive(Debug, Default)]
struct RuntimeMetrics {
    accepted: AtomicU64,
    refused_full: AtomicU64,
    control_tasks_completed: AtomicU64,
    control_tasks_failed: AtomicU64,
    admission_failures: AtomicU64,
}

/// Public read-only runtime metrics. Counts only, never identities, tickets,
/// paths, or packet data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2GatewayRuntimeSnapshot {
    pub accepted: u64,
    pub refused_full: u64,
    pub control_tasks_completed: u64,
    pub control_tasks_failed: u64,
    pub admission_failures: u64,
    pub control_tasks_running: usize,
    pub maximum_connections: usize,
    pub sessions: usize,
    pub pool_active: usize,
    pub pool_pending: usize,
}

/// Final metrics from [`V2GatewayRuntime::stop`].
#[derive(Debug)]
pub struct V2GatewayRuntimeStopMetrics {
    pub runtime: V2GatewayRuntimeSnapshot,
    pub setup: V2GatewaySetupMetrics,
    pub sessions_closed: usize,
}

/// Outcome of one admitted control task (bounded messages, then exit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ControlTaskOutcome {
    messages: u64,
    completed: bool,
}

/// Admission-only gateway runtime. Owns setup (pool, sessions, sweeps),
/// the admission handler, the mTLS listener with its endpoint, the bounded
/// control-task [`JoinSet`], and explicit shutdown state.
///
/// Construct with [`V2GatewayRuntime::start`], drive with
/// [`V2GatewayRuntime::run`], and terminate with
/// [`V2GatewayRuntime::stop`]. Dropping without `stop` aborts tasks via
/// `JoinSet`/`setup` drop (no leak) but skips the graceful session-close
/// sweep; always call `stop`.
pub struct V2GatewayRuntime {
    setup: V2GatewaySetup,
    handler: Arc<AdmissionHandler<TicketVerifier>>,
    listener: V2AdmissionListener<TicketVerifier>,
    tasks: JoinSet<ControlTaskOutcome>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    metrics: RuntimeMetrics,
    maximum_connections: usize,
    maximum_control_messages_per_connection: u64,
}

impl std::fmt::Debug for V2GatewayRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("V2GatewayRuntime(REDACTED)")
    }
}

impl V2GatewayRuntime {
    /// Starts the admission-only runtime from a validated configuration.
    ///
    /// Opens the self-hosted atomic lease journal and the durable
    /// single-gateway redemption journal (fail closed on corrupt or
    /// gateway-mismatched data), creates the authoritative session map, the
    /// bounded admission handler, the autonomous sweeps, and the mTLS
    /// listener. Runs startup recovery (session/pool sweeps with session
    /// close for expired leases) before returning. Must be called inside a
    /// Tokio runtime (sweeps spawn ticker plus worker tasks).
    pub fn start(config: V2GatewayConfig) -> Result<Self, V2GatewayRuntimeError> {
        // Fail closed on the V1 shared secret even though `from_file` already
        // checked: the runtime never runs with it set, however it was built.
        if std::env::var_os("STREAMGUARD_SECRET").is_some() {
            return Err(V2GatewayRuntimeError::SharedSecretPresent);
        }
        // Move every validated value out of the redacted config. After this
        // point no config object remains; the runtime owns setup, handler,
        // and listener directly (never logging any of the moved values).
        let (
            bind_addr,
            _gateway_name,
            gateway_name_string,
            gateway_identity,
            device_trust,
            controller_trust,
            ticket_verifier,
            safe_mode_policy,
            lease_journal_path,
            replay_journal_path,
            replay_capacity,
            pool_config,
            session_config,
            limiter_config,
            handshake_timeout,
            control_stream_timeout,
            control_deadlines,
            control_frame_limit,
            maximum_connections,
            maximum_control_messages_per_connection,
            session_sweep,
            pool_sweep,
        ) = config.into_parts();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        // Dual clock for lease persistence: monotonic drives in-memory TTLs,
        // wall drives the durable journal (see `PoolTime`). Both derive from
        // the same `MonotonicClock` so a restart converts remaining wall time
        // back to monotonic without skew within one process lifetime.
        let clock: Arc<MonotonicClock> = Arc::new(MonotonicClock::new());
        // Self-hosted atomic local lease journal only: the config gate already
        // rejected any other lease mode, and `AddressPoolMode::SelfHosted` is
        // the only variant constructed here by construction. The open uses a
        // real wall clock so leases survive a restart (monotonic alone would
        // reset to near zero and mis-recover).
        let pool_open_time = super::persistence::PoolTime::from_monotonic_and_wall_seconds(
            clock.monotonic_ms(),
            clock.unix_seconds(),
        );
        let pool = Arc::new(
            AddressPool::open_at_time(
                pool_config,
                AddressPoolMode::SelfHosted { journal_path: lease_journal_path.clone() },
                pool_open_time,
            )
            .map_err(|_| V2GatewayRuntimeError::Unavailable)?,
        );
        Self::enforce_journal_permissions(&lease_journal_path)?;
        // Durable local single-gateway ticket redemption journal. A journal
        // created for another gateway name fails closed here (no cross-gateway
        // sharing); multi-gateway scopes were already rejected at config load.
        let replay = ReplayCache::open_durable(&replay_journal_path, &gateway_name_string, replay_capacity, now_unix)
            .map_err(|_| V2GatewayRuntimeError::ReplayStore)?;
        Self::enforce_journal_permissions(&replay_journal_path)?;

        let sessions = Arc::new(
            V2SessionManager::with_cleanup(
                session_config,
                vec![Arc::clone(&pool) as Arc<dyn super::session_manager::SessionCleanup>],
            )
            .map_err(|_| V2GatewayRuntimeError::InvalidConfiguration)?,
        );
        let limiter = HandshakeAdmissionLimiter::new(limiter_config)
            .map_err(|_| V2GatewayRuntimeError::InvalidConfiguration)?;
        let handler = Arc::new(AdmissionHandler::new(ticket_verifier, limiter, replay, Arc::clone(&sessions)));
        let setup = V2GatewaySetup::start_with_clock(
            Arc::clone(&pool),
            Arc::clone(&sessions),
            session_sweep,
            pool_sweep,
            Arc::clone(&clock),
        );
        // Startup recovery: sweep sessions and leases with the current clock
        // so expired state from a previous run never lingers. Pool expiries
        // close their sessions (idempotent) before serving traffic.
        let now_ms = setup.clock().monotonic_ms();
        handler.sweep(now_ms).map_err(|_| V2GatewayRuntimeError::Unavailable)?;
        let expired_leases = pool.sweep(now_ms);
        for expired in expired_leases {
            let _ = handler.close_session_by_id(expired);
        }
        // Re-run the session sweep after lease-driven closes so tombstones and
        // admissions settle deterministically before the first accept.
        handler.sweep(now_ms).map_err(|_| V2GatewayRuntimeError::Unavailable)?;

        let extractor: Arc<CertHashDeviceExtractor> = Arc::new(CertHashDeviceExtractor);
        // The controller trust snapshot moves into a shared `Arc` so admission
        // validates against the same snapshot for the runtime lifetime
        // (rotation is a restart in this entrypoint, documented).
        let trust = Arc::new(controller_trust);
        let template = SessionAdmitTemplate::new(safe_mode_policy);
        let listener_config = super::listener::V2AdmissionListenerConfig {
            handshake_timeout,
            control_stream_timeout,
            control_deadlines,
            control_frame_limit,
        };
        // Borrow the TLS handles only for `bind`: the endpoint clones the
        // rustls configs it needs, so no reference escapes this call.
        let listener = V2AdmissionListener::bind(
            bind_addr,
            V2AdmissionTls { gateway_identity: gateway_identity.as_ref(), device_trust: &device_trust },
            V2AdmissionListenerSetup {
                handler: Arc::clone(&handler),
                extractor: Arc::clone(&extractor) as Arc<dyn VerifiedPeerDeviceIdentityExtractor>,
                trust: Arc::clone(&trust),
                template,
                address_pool: Arc::clone(&pool),
                config: listener_config,
            },
        )
        .map_err(|_| V2GatewayRuntimeError::Listener)?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Keep the setup alive alongside the listener: the per-accept sweeps
        // stay as a fast path, but the setup-owned autonomous tasks are the
        // expiry guarantee. Hold `setup` (not just its Arcs) so `stop` joins.
        Ok(Self {
            setup,
            handler,
            listener,
            tasks: JoinSet::new(),
            shutdown_tx,
            shutdown_rx,
            metrics: RuntimeMetrics::default(),
            maximum_connections,
            maximum_control_messages_per_connection,
        })
    }

    /// Enforces private (0600-style) permissions on a journal file after it is
    /// created or opened. A missing file (empty journal, created on first
    /// persist) is not an error: its parent was already validated as secure
    /// by the configuration gate. Best-effort hardening: a chmod failure
    /// fails closed only when the file remains permissive afterwards. Never
    /// logs paths.
    fn enforce_journal_permissions(path: &Path) -> Result<(), V2GatewayRuntimeError> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(V2GatewayRuntimeError::FilesystemRef),
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(V2GatewayRuntimeError::FilesystemRef);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                // Harden a newly created 0644 journal to 0600; a pre-existing
                // permissive journal fails closed when the chmod cannot fix it.
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                let fixed = std::fs::symlink_metadata(path).map_err(|_| V2GatewayRuntimeError::FilesystemRef)?;
                if fixed.permissions().mode() & 0o077 != 0 {
                    return Err(V2GatewayRuntimeError::FilesystemRef);
                }
            }
        }
        Ok(())
    }

    /// Local address of the bound QUIC endpoint.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, V2GatewayRuntimeError> {
        self.listener.local_addr().map_err(|_| V2GatewayRuntimeError::Listener)
    }

    /// Current read-only snapshot (counts only, never identities or secrets).
    #[must_use]
    pub fn snapshot(&self) -> V2GatewayRuntimeSnapshot {
        V2GatewayRuntimeSnapshot {
            accepted: self.metrics.accepted.load(Ordering::Relaxed),
            refused_full: self.metrics.refused_full.load(Ordering::Relaxed),
            control_tasks_completed: self.metrics.control_tasks_completed.load(Ordering::Relaxed),
            control_tasks_failed: self.metrics.control_tasks_failed.load(Ordering::Relaxed),
            admission_failures: self.metrics.admission_failures.load(Ordering::Relaxed),
            control_tasks_running: self.tasks.len(),
            maximum_connections: self.maximum_connections,
            sessions: self.setup.session_snapshot().sessions,
            pool_active: self.setup.pool_snapshot().active,
            pool_pending: self.setup.pool_snapshot().pending,
        }
    }

    /// Drives the bounded accept loop until shutdown or endpoint close.
    ///
    /// Accepts one mTLS admission at a time; each admitted connection spawns
    /// exactly one bounded control task (at most `maximum_connections`
    /// concurrently; excess admissions unwind their session and lease and
    /// count `refused_full`). Control tasks process at most
    /// `maximum_control_messages_per_connection` requests with the configured
    /// control deadlines, then exit. Returns when shutdown is signaled or the
    /// endpoint closes.
    pub async fn run(&mut self) {
        let clock = Arc::clone(self.setup.clock());
        loop {
            if *self.shutdown_rx.borrow() {
                break;
            }
            // Reap completed control tasks without blocking so slots free
            // promptly and metrics stay current.
            while let Some(outcome) = self.tasks.try_join_next() {
                self.record_task_outcome(Some(outcome));
            }
            if self.tasks.len() >= self.maximum_connections {
                tokio::select! {
                    _ = self.shutdown_rx.changed() => break,
                    joined = self.tasks.join_next() => {
                        self.record_task_outcome(joined);
                    }
                }
                continue;
            }
            let now = AdmissionTime {
                unix_seconds: clock.unix_seconds(),
                monotonic_millis: clock.monotonic_ms(),
            };
            // Borrow disjoint fields so the accept future and the task set
            // can coexist in one `select!` without holding `self` twice.
            let (listener, tasks, shutdown_rx, handler, setup, metrics, max_tasks, max_messages) = (
                &self.listener,
                &mut self.tasks,
                &mut self.shutdown_rx,
                &self.handler,
                &self.setup,
                &self.metrics,
                self.maximum_connections,
                self.maximum_control_messages_per_connection,
            );
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                accept = listener.accept_one_at(now) => {
                    match accept {
                        Ok(admitted) => {
                            if tasks.len() >= max_tasks {
                                // Bound raced the accept: unwind the just-
                                // committed session and lease (idempotent)
                                // so no address leaks, then count the refusal.
                                let session_id = admitted.admission().owner().session_id();
                                drop(admitted);
                                let _ = handler.close_session_by_id(session_id);
                                let _ = Arc::clone(setup.pool()).release_async(session_id).await;
                                metrics.refused_full.fetch_add(1, Ordering::Relaxed);
                            } else {
                                let task_clock: Arc<dyn Clock> = Arc::clone(&clock);
                                tasks.spawn(drive_control_connection(admitted, task_clock, max_messages));
                                metrics.accepted.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            // Handshake, mTLS, ticket, replay, pool, or control
                            // failures all land here without allocating a
                            // session (the listener unwinds). Count and keep
                            // serving; shutdown/endpoint-close also lands here
                            // and the next loop iteration exits via the watch.
                            metrics.admission_failures.fetch_add(1, Ordering::Relaxed);
                            if *shutdown_rx.borrow() {
                                break;
                            }
                            // Avoid a hot loop when the endpoint is closed:
                            // the watch will already be set by `stop`, but a
                            // bare endpoint failure without shutdown still
                            // yields to the runtime before retrying.
                            tokio::task::yield_now().await;
                        }
                    }
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    // A control task finished while no accept was pending:
                    // record its outcome (frees its slot via JoinSet).
                    let metrics_ref: &RuntimeMetrics = metrics;
                    match joined {
                        Some(Ok(outcome)) => {
                            if outcome.completed {
                                metrics_ref.control_tasks_completed.fetch_add(1, Ordering::Relaxed);
                            } else {
                                metrics_ref.control_tasks_failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Some(Err(_)) => {
                            metrics_ref.control_tasks_failed.fetch_add(1, Ordering::Relaxed);
                        }
                        None => {}
                    }
                }
            }
        }
    }

    fn record_task_outcome(
        &self,
        joined: Option<Result<ControlTaskOutcome, tokio::task::JoinError>>,
    ) {
        match joined {
            Some(Ok(outcome)) => {
                if outcome.completed {
                    self.metrics.control_tasks_completed.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.metrics.control_tasks_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            Some(Err(_)) => {
                self.metrics.control_tasks_failed.fetch_add(1, Ordering::Relaxed);
            }
            None => {}
        }
    }

    /// Signals shutdown, closes the endpoint, joins control tasks and sweeps,
    /// closes every session (releasing leases via cleanup), drains persistence
    /// owner queues with bounded deadlines, and returns final metrics.
    /// Never hangs indefinitely: control tasks are aborted, sweeps join with
    /// hard timeouts, and owner queues join with `shutdown_timeout`
    /// (stalled workers time out and detach, counted). Idempotent: a second
    /// call returns the same snapshot without hanging.
    pub async fn stop(&mut self) -> V2GatewayRuntimeStopMetrics {
        let _ = self.shutdown_tx.send(true);
        self.listener.close();
        // Prompt cancellation: control tasks block on bounded control reads,
        // so abort rather than waiting out their deadlines. Abort drops each
        // `V2AdmittedConnection`, whose `Drop` detaches its path/connection
        // exactly once; sessions are closed explicitly below.
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        // Join both supervised sweeps (bounded, no indefinite wait).
        let setup_metrics = self.setup.stop().await;
        // Close every remaining session; cleanup quarantines leases in memory
        // (no blocking I/O here) while the journal files retain the durable
        // entries that block reuse across a restart.
        let sessions_closed = self.setup.sessions().close_all();
        // Best-effort expiry pass so a clean stop leaves no stale Reserved
        // lease behind (owner queue, `io_timeout` fail-closed, never hangs);
        // quarantined durable deletes retry on next startup.
        let sweep_now = super::persistence::PoolTime::from_monotonic_and_wall_seconds(
            self.setup.clock().monotonic_ms(),
            self.setup.clock().unix_seconds(),
        );
        let _ = Arc::clone(self.setup.pool()).sweep_at_time_async(sweep_now).await;
        // Drain persistence owner queues with bounded deadlines (never hangs);
        // stalled workers time out and detach, counted in their snapshots.
        let _ = Arc::clone(self.setup.pool()).stop_persistence().await;
        let _ = self.handler.stop_persistence().await;
        V2GatewayRuntimeStopMetrics {
            runtime: self.snapshot(),
            setup: setup_metrics,
            sessions_closed,
        }
    }
}

/// Drives one admitted reliable control stream to its bounded end: at most
/// `max_messages` successful control requests, then exit. Any control error
/// (closed stream, invalid request, sweep failure) ends the task as failed.
/// Never logs packet contents, tickets, or identities.
async fn drive_control_connection(
    mut admitted: super::listener::V2AdmittedConnection<TicketVerifier>,
    clock: Arc<dyn Clock>,
    max_messages: u64,
) -> ControlTaskOutcome {
    let mut messages = 0u64;
    while messages < max_messages {
        // Wall-aware renewal clock: monotonic drives TTLs, wall drives the
        // durable lease journal (see `PoolTime`). Valid control renews the
        // Active lease through the bounded owner queue before expiry; renewal
        // failures fail closed (no `Ack`/`PathAttached`).
        let now = super::persistence::PoolTime::from_monotonic_and_wall_seconds(
            clock.monotonic_ms(),
            clock.unix_seconds(),
        );
        match admitted.handle_next_control_at_time(now).await {
            Ok(()) => {
                messages = messages.saturating_add(1);
            }
            Err(_) => {
                return ControlTaskOutcome { messages, completed: false };
            }
        }
    }
    ControlTaskOutcome { messages, completed: true }
}

