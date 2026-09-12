//! Bounded V2 ticket admission backed by the authoritative session map.
//!
//! This module has no V1 session, path, TUN, payload, or flow dependency.
//! WP-202 owns the real V2 session/path lifecycle; this module verifies tickets
//! and reserves admission without allocating packet, path, TUN, or flow state.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sg_auth::device::{AdmissionTicketValidator, validate_admission_ticket};
use sg_auth::ticket::{
    ControllerTrustSnapshot, OrganizationId, REPLAY_EXPIRY_SKEW_SECONDS, TicketId,
    TicketVerificationError, VerifiedAdmissionTicket,
};
use sg_core::v2::{DeviceId, PathId, SessionId};
use sg_protocol::v2::control::{AdmissionTicket, ControlMessage, MAX_GATEWAY_NAME_LEN};
use thiserror::Error;

use super::session_manager::{AdmissionReservation, AuthenticatedConnection, GatewayAttachReservation, V2SessionManager, V2SessionManagerError, V2SessionManagerSnapshot};
use sg_session::v2::PathBinding;

/// A decoded V2 `ClientHello` accepted only after the bounded control codec.
#[derive(Clone)]
pub struct BoundedClientHello {
    device_id: DeviceId,
    requested_gateway: String,
    ticket: AdmissionTicket,
}

impl BoundedClientHello {
    pub fn from_control_message(message: &ControlMessage) -> Result<Self, AdmissionError> {
        let ControlMessage::ClientHello { device_id, requested_gateway, ticket } = message else {
            return Err(AdmissionError::InvalidHello);
        };
        if requested_gateway.is_empty()
            || requested_gateway.len() > MAX_GATEWAY_NAME_LEN
            || !requested_gateway.is_ascii()
        {
            return Err(AdmissionError::InvalidHello);
        }
        Ok(Self {
            device_id: *device_id,
            requested_gateway: requested_gateway.clone(),
            ticket: ticket.clone(),
        })
    }

    #[must_use]
    pub fn requested_gateway(&self) -> &str {
        &self.requested_gateway
    }
}

impl fmt::Debug for BoundedClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedClientHello(REDACTED)")
    }
}

/// Gateway admission time in two independent domains. `monotonic_millis`
/// drives TTL-based resource policy (handshake budgets, replay skew); the
/// session manager's monotonic deadline is derived from it. `unix_seconds`
/// is real wall time since the Unix epoch and is the only value compared
/// against ticket claims. Production callers derive this from the lifecycle
/// [`Clock`](super::session_manager::Clock); tests inject it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionTime {
    pub unix_seconds: u64,
    pub monotonic_millis: u64,
}

/// Opaque mTLS peer identity. Only the V2 listener may construct this after
/// `v2_peer_device_identity` has extracted the identity from Quinn's verified
/// rustls chain. It intentionally has no public constructor or accessor.
#[derive(Clone, Copy)]
pub(super) struct VerifiedPeer(DeviceId);

pub(super) fn verified_peer_from_transport(device_id: DeviceId) -> VerifiedPeer {
    VerifiedPeer(device_id)
}

/// Full V2 ownership retained by the pre-WP-202 registry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionOwner {
    session_id: SessionId,
    device_id: DeviceId,
    organization_id: OrganizationId,
}

impl SessionOwner {
    fn from_ticket(ticket: &VerifiedAdmissionTicket) -> Self {
        Self {
            session_id: ticket.session_id(),
            device_id: ticket.device_id(),
            organization_id: ticket.organization_id(),
        }
    }

    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    pub fn organization_id(&self) -> OrganizationId {
        self.organization_id
    }
}

impl fmt::Debug for SessionOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionOwner(REDACTED)")
    }
}

/// Successful verification data used by the listener's SessionAdmit builder.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdmissionAccepted {
    owner: SessionOwner,
    expires_at_unix_seconds: u64,
    policy_version: u64,
    reservation: AdmissionReservation,
}

impl AdmissionAccepted {
    #[must_use]
    pub fn owner(&self) -> SessionOwner {
        self.owner
    }

    #[must_use]
    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    #[must_use]
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }

    fn reservation(&self) -> AdmissionReservation {
        self.reservation
    }
}

impl fmt::Debug for AdmissionAccepted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionAccepted(REDACTED)")
    }
}

/// Bounded time for durable replay journal I/O through the supervised owner
/// queue. A durable consume that cannot persist within this budget fails
/// closed with [`ReplayCacheError::Unavailable`] (mapped to
/// [`AdmissionError::Unavailable`] at the admission boundary) so a stalled
/// disk never hangs the async admission listener. The timed-out owner write
/// may still complete later; the ticket is then treated as consumed (a retry
/// observes `Replay`), which is fail-closed: no `SessionAdmit` is ever
/// written without a durable redemption. Matches
/// [`PERSISTENCE_IO_TIMEOUT`](super::persistence::PERSISTENCE_IO_TIMEOUT).
pub const REPLAY_JOURNAL_IO_TIMEOUT: Duration = Duration::from_millis(500);

/// A bounded, atomic, fail-closed replay cache. Live entries are never evicted
/// for capacity; only expiry plus fixed skew permits removal.
///
/// Two modes share this type so the admission handler never branches:
///
/// - **In-memory** (`ReplayCache::new`): single-run tests and non-durable
///   callers. No file I/O.
/// - **Durable single-gateway** (`ReplayCache::open_durable`): the
///   admission-only entrypoint's local redemption journal
///   (`super::replay`). Every `consume` persists the full snapshot with the
///   atomic temp-file plus rename protocol while holding the single entries
///   lock, so a crash leaves the old or the new journal, never a half-write.
///   The journal header binds the file to one gateway name; opening a journal
///   created for another gateway fails closed.
///
/// Blocking: the sync `consume` performs file I/O on its caller's thread
/// while holding the single entries lock (single-guard serialization, matching
/// the lease journal). Production async callers must use `consume_async`,
/// which routes the same critical section through the supervised
/// [`PersistenceOwner`](super::persistence::PersistenceOwner) (bounded queue,
/// hard cap, `io_timeout` fail-closed) and never holds the entries lock or
/// performs file I/O on the async executor thread. No detached
/// `spawn_blocking` flood: at most `queue_capacity` consumes are ever queued.
pub struct ReplayCache {
    capacity: usize,
    entries: Mutex<BTreeMap<TicketId, u64>>,
    replay_rejected: AtomicU64,
    capacity_rejected: AtomicU64,
    expired: AtomicU64,
    journal_path: Option<std::path::PathBuf>,
    journal_gateway: Option<String>,
    persistence: Option<Arc<super::persistence::PersistenceOwner>>,
    #[cfg(test)]
    test_gate: Mutex<Option<std::sync::Arc<TestGate>>>,
}

/// Deterministic blocked-journal seam for tests. The gate is one-shot: the
/// first durable `consume` that reaches the journal rewrite signals `entered`
/// and blocks on `proceed` while still holding the single entries lock on its
/// blocking thread (exactly like a stalled disk holding serialization).
/// Subsequent consumes block behind the entries lock and also fail closed via
/// `consume_async`'s timeout until the test sends `proceed`. Production code
/// never installs a gate.
#[cfg(test)]
#[derive(Debug)]
struct TestGate {
    entered: std::sync::mpsc::Sender<()>,
    proceed: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

#[cfg(test)]
impl TestGate {
    fn install(cache: &ReplayCache) -> (std::sync::Arc<Self>, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
        let gate = std::sync::Arc::new(Self {
            entered: entered_tx,
            proceed: std::sync::Mutex::new(Some(proceed_rx)),
        });
        *cache.test_gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(std::sync::Arc::clone(&gate));
        (gate, entered_rx, proceed_tx)
    }
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Result<Self, AdmissionError> {
        if capacity == 0 || capacity > super::replay::MAX_REPLAY_ENTRIES_HARD_CAP {
            return Err(AdmissionError::InvalidConfiguration);
        }
        Ok(Self {
            capacity,
            entries: Mutex::new(BTreeMap::new()),
            replay_rejected: AtomicU64::new(0),
            capacity_rejected: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            journal_path: None,
            journal_gateway: None,
            persistence: None,
            #[cfg(test)]
            test_gate: Mutex::new(None),
        })
    }

    /// Opens (or creates) the durable single-gateway redemption journal.
    ///
    /// Missing file means an empty journal. Corrupt, trailing-data,
    /// over-bound, duplicate, or gateway-mismatched journals fail closed with
    /// [`AdmissionError::ReplayStore`]. Expired entries are pruned in memory
    /// and the file is rewritten to its canonical form; a rewrite failure
    /// also fails closed. Capacity is bounded by
    /// `MAX_REPLAY_ENTRIES_HARD_CAP`.
    pub fn open_durable(
        journal_path: &std::path::Path,
        gateway_name: &str,
        capacity: usize,
        now_unix_seconds: u64,
    ) -> Result<Self, AdmissionError> {
        if capacity == 0 || capacity > super::replay::MAX_REPLAY_ENTRIES_HARD_CAP {
            return Err(AdmissionError::InvalidConfiguration);
        }
        let loaded = super::replay::read_replay_journal(journal_path, gateway_name, now_unix_seconds)
            .map_err(|_| AdmissionError::ReplayStore)?;
        if loaded.len() > capacity {
            return Err(AdmissionError::ReplayStore);
        }
        let cache = Self {
            capacity,
            entries: Mutex::new(loaded),
            replay_rejected: AtomicU64::new(0),
            capacity_rejected: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            journal_path: Some(journal_path.to_path_buf()),
            journal_gateway: Some(gateway_name.to_owned()),
            persistence: Some(Arc::new(super::persistence::PersistenceOwner::start(
                super::persistence::PersistenceConfig::default(),
            ))),
            #[cfg(test)]
            test_gate: Mutex::new(None),
        };
        // Canonicalize the file (pruned expiries, sorted order, valid header)
        // so growth stays bounded across restarts. A failure fails closed:
        // the gateway must not run with an unmaintainable journal.
        cache.rewrite_journal_locked().map_err(|_| AdmissionError::ReplayStore)?;
        Ok(cache)
    }

    /// Rewrites the journal from the current in-memory snapshot while holding
    /// the single entries lock across the blocking file rewrite (single-guard
    /// serialization, matching the lease journal). No-op when this cache is
    /// in-memory. Construction-time only: the cache is not yet shared, so no
    /// concurrent consumer can interleave.
    fn rewrite_journal_locked(&self) -> Result<(), ReplayCacheError> {
        let (Some(path), Some(gateway)) = (self.journal_path.as_ref(), self.journal_gateway.as_ref()) else {
            return Ok(());
        };
        let entries = self.entries.lock().map_err(|_| ReplayCacheError::Unavailable)?;
        super::replay::rewrite_replay_journal(path, gateway, &entries)
            .map_err(|_| ReplayCacheError::Unavailable)?;
        Ok(())
    }

    fn consume(
        &self,
        ticket_id: TicketId,
        ticket_expiry_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<(), ReplayCacheError> {
        let mut entries = self.entries.lock().map_err(|_| ReplayCacheError::Unavailable)?;
        let before = entries.len();
        entries.retain(|_, retained_until| *retained_until > now_unix_seconds);
        self.expired.fetch_add((before - entries.len()) as u64, Ordering::Relaxed);
        if entries.contains_key(&ticket_id) {
            self.replay_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(ReplayCacheError::Replay);
        }
        if entries.len() >= self.capacity {
            self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(ReplayCacheError::Capacity);
        }
        entries.insert(ticket_id, ticket_expiry_unix_seconds.saturating_add(REPLAY_EXPIRY_SKEW_SECONDS));
        // Durable single-guard: persist the full snapshot while holding the
        // single entries lock so concurrent consumes serialize and the file
        // never drops a ticket (lost-update). This blocking file rewrite runs
        // on the caller's thread: production async callers must use
        // `consume_async` (bounded `spawn_blocking` with timeout) so no async
        // executor thread ever blocks here and no entries lock is ever held
        // across an await. A rewrite failure rolls back the in-memory insert
        // and fails closed, so the ticket can be retried after the disk
        // recovers rather than burning a live ticket.
        if let (Some(path), Some(gateway)) = (self.journal_path.as_ref(), self.journal_gateway.as_ref()) {
            #[cfg(test)]
            {
                // Deterministic blocked-journal seam (one-shot): when the test
                // installs a gate, signal `entered` and block on `proceed`
                // while still holding the single entries lock on this
                // (blocking) thread, exactly like a stalled disk holding
                // serialization. The async caller times out via
                // `consume_async` without holding any lock on its own thread.
                // The gate is consumed here so only the first rewrite blocks.
                let gate = self
                    .test_gate
                    .lock()
                    .map(|mut guard| guard.take())
                    .unwrap_or(None);
                if let Some(gate) = gate {
                    let _ = gate.entered.send(());
                    if let Ok(proceed) = gate.proceed.lock() {
                        if let Some(receiver) = proceed.as_ref() {
                            let _ = receiver.recv();
                        }
                    }
                }
            }
            let snapshot = entries.clone();
            if super::replay::rewrite_replay_journal(path, gateway, &snapshot).is_err() {
                entries.remove(&ticket_id);
                return Err(ReplayCacheError::Unavailable);
            }
        }
        Ok(())
    }

    /// Bounded async consume for the admission listener. In-memory caches run
    /// inline (no I/O, brief lock, no owner). Durable caches route the same
    /// single-guard critical section through the supervised owner queue
    /// (hard cap, `try_send` backpressure, `io_timeout` fail-closed), so the
    /// async listener never holds the entries lock and never performs file
    /// I/O on its executor thread. `Full`/`Timeout`/`Closed` map to
    /// `Unavailable` (fail closed, time bounded); the blocked owner write may
    /// still complete later, in which case a retry observes `Replay` rather
    /// than double-admitting. No detached `spawn_blocking` flood.
    async fn consume_async(
        self: Arc<Self>,
        ticket_id: TicketId,
        ticket_expiry_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<(), ReplayCacheError> {
        if !self.is_durable() {
            return self.consume(ticket_id, ticket_expiry_unix_seconds, now_unix_seconds);
        }
        let Some(owner) = &self.persistence else {
            return Err(ReplayCacheError::Unavailable);
        };
        let cache = Arc::clone(&self);
        owner
            .execute(move || cache.consume(ticket_id, ticket_expiry_unix_seconds, now_unix_seconds))
            .await
            .map_err(|_| ReplayCacheError::Unavailable)?
    }

    /// Closes the owner queue (no new persistence work) and joins the worker
    /// with the bounded shutdown deadline. Never hangs indefinitely.
    /// Idempotent. In-memory caches are a no-op.
    pub async fn stop_persistence(&self) -> Option<super::persistence::PersistenceSnapshot> {
        if let Some(owner) = &self.persistence {
            Some(owner.stop().await)
        } else {
            None
        }
    }

    /// Owner-queue metrics snapshot, if durable (counts only).
    #[must_use]
    pub fn persistence_snapshot(&self) -> Option<super::persistence::PersistenceSnapshot> {
        self.persistence.as_ref().map(|owner| owner.snapshot())
    }

    /// True when this cache persists to the single-gateway journal.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.journal_path.is_some()
    }

    #[must_use]
    pub fn snapshot(&self) -> ReplayCacheSnapshot {
        let entries = self.entries.lock().map(|entries| entries.len()).unwrap_or(0);
        ReplayCacheSnapshot {
            entries,
            capacity: self.capacity,
            replay_rejected: self.replay_rejected.load(Ordering::Relaxed),
            capacity_rejected: self.capacity_rejected.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            durable: self.journal_path.is_some(),
        }
    }
}

impl fmt::Debug for ReplayCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplayCache(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayCacheSnapshot {
    pub entries: usize,
    pub capacity: usize,
    pub replay_rejected: u64,
    pub capacity_rejected: u64,
    pub expired: u64,
    /// True when this cache persists to the single-gateway journal.
    pub durable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayCacheError {
    Replay,
    Capacity,
    Unavailable,
}

/// Limits both pre-handshake and post-handshake ticket verification resource
/// use. Permits are RAII values containing no lock guard, so they are safe to
/// hold while awaiting Quinn or framed-control operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeAdmissionLimiterConfig {
    pub source_capacity: usize,
    pub source_ttl_millis: u64,
    pub maximum_per_source_in_flight: usize,
    pub maximum_global_in_flight: usize,
    pub maximum_verification_budget_millis: u64,
}

#[derive(Clone)]
pub struct HandshakeAdmissionLimiter {
    config: HandshakeAdmissionLimiterConfig,
    state: Arc<Mutex<LimiterState>>,
    source_capacity_rejected: Arc<AtomicU64>,
    source_in_flight_rejected: Arc<AtomicU64>,
    global_in_flight_rejected: Arc<AtomicU64>,
    deadline_rejected: Arc<AtomicU64>,
    expired: Arc<AtomicU64>,
}

struct LimiterState {
    sources: HashMap<IpAddr, SourceState>,
    global_in_flight: usize,
}

struct SourceState {
    in_flight: usize,
    last_seen_millis: u64,
}

impl HandshakeAdmissionLimiter {
    pub fn new(config: HandshakeAdmissionLimiterConfig) -> Result<Self, AdmissionError> {
        if config.source_capacity == 0
            || config.source_ttl_millis == 0
            || config.maximum_per_source_in_flight == 0
            || config.maximum_global_in_flight == 0
            || config.maximum_verification_budget_millis == 0
        {
            return Err(AdmissionError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            state: Arc::new(Mutex::new(LimiterState { sources: HashMap::new(), global_in_flight: 0 })),
            source_capacity_rejected: Arc::new(AtomicU64::new(0)),
            source_in_flight_rejected: Arc::new(AtomicU64::new(0)),
            global_in_flight_rejected: Arc::new(AtomicU64::new(0)),
            deadline_rejected: Arc::new(AtomicU64::new(0)),
            expired: Arc::new(AtomicU64::new(0)),
        })
    }

    fn acquire(
        &self,
        source: IpAddr,
        started_at_millis: u64,
        now_millis: u64,
    ) -> Result<AdmissionPermit, LimiterError> {
        if now_millis.saturating_sub(started_at_millis) > self.config.maximum_verification_budget_millis {
            self.deadline_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(LimiterError::BudgetExceeded);
        }
        let mut state = self.state.lock().map_err(|_| LimiterError::Unavailable)?;
        let before = state.sources.len();
        state.sources.retain(|_, entry| {
            entry.in_flight != 0
                || now_millis.saturating_sub(entry.last_seen_millis) < self.config.source_ttl_millis
        });
        self.expired.fetch_add((before - state.sources.len()) as u64, Ordering::Relaxed);
        if state.global_in_flight >= self.config.maximum_global_in_flight {
            self.global_in_flight_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(LimiterError::GlobalInFlight);
        }
        if !state.sources.contains_key(&source) {
            if state.sources.len() >= self.config.source_capacity {
                self.source_capacity_rejected.fetch_add(1, Ordering::Relaxed);
                return Err(LimiterError::SourceCapacity);
            }
            state.sources.insert(source, SourceState { in_flight: 0, last_seen_millis: now_millis });
        }
        let entry = state.sources.get_mut(&source).ok_or(LimiterError::Unavailable)?;
        if entry.in_flight >= self.config.maximum_per_source_in_flight {
            self.source_in_flight_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(LimiterError::SourceInFlight);
        }
        entry.in_flight += 1;
        entry.last_seen_millis = now_millis;
        state.global_in_flight += 1;
        Ok(AdmissionPermit { source, state: Arc::clone(&self.state) })
    }

    #[must_use]
    pub fn snapshot(&self) -> HandshakeAdmissionLimiterSnapshot {
        let (source_entries, global_in_flight) = self
            .state
            .lock()
            .map(|state| (state.sources.len(), state.global_in_flight))
            .unwrap_or((0, 0));
        HandshakeAdmissionLimiterSnapshot {
            source_entries,
            source_capacity: self.config.source_capacity,
            global_in_flight,
            global_in_flight_capacity: self.config.maximum_global_in_flight,
            source_capacity_rejected: self.source_capacity_rejected.load(Ordering::Relaxed),
            source_in_flight_rejected: self.source_in_flight_rejected.load(Ordering::Relaxed),
            global_in_flight_rejected: self.global_in_flight_rejected.load(Ordering::Relaxed),
            deadline_rejected: self.deadline_rejected.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
        }
    }
}

impl fmt::Debug for HandshakeAdmissionLimiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandshakeAdmissionLimiter(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeAdmissionLimiterSnapshot {
    pub source_entries: usize,
    pub source_capacity: usize,
    pub global_in_flight: usize,
    pub global_in_flight_capacity: usize,
    pub source_capacity_rejected: u64,
    pub source_in_flight_rejected: u64,
    pub global_in_flight_rejected: u64,
    pub deadline_rejected: u64,
    pub expired: u64,
}

pub(super) struct AdmissionPermit {
    source: IpAddr,
    state: Arc<Mutex<LimiterState>>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.global_in_flight = state.global_in_flight.saturating_sub(1);
            if let Some(entry) = state.sources.get_mut(&self.source) {
                entry.in_flight = entry.in_flight.saturating_sub(1);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimiterError {
    BudgetExceeded,
    SourceCapacity,
    SourceInFlight,
    GlobalInFlight,
    Unavailable,
}

/// Counters contain no ticket, claim, device, organization, or source labels.
#[derive(Default)]
struct AdmissionMetrics {
    admitted: AtomicU64,
    limiter_rejected: AtomicU64,
    ticket_rejected: AtomicU64,
    controller_unavailable: AtomicU64,
    provisioning_rejected: AtomicU64,
}

/// Public read-only admission metrics, including bounded-state occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionMetricsSnapshot {
    pub admitted: u64,
    pub limiter_rejected: u64,
    pub ticket_rejected: u64,
    pub controller_unavailable: u64,
    pub provisioning_rejected: u64,
    pub replay: ReplayCacheSnapshot,
    pub limiter: HandshakeAdmissionLimiterSnapshot,
    pub sessions: V2SessionManagerSnapshot,
}

/// Ticket admission is deliberately crate-private. The only public ingress is
/// the V2 listener, which creates `VerifiedPeer` from Quinn's verified chain.
///
/// The replay cache is shared via `Arc` so the async admission path can route
/// it through the supervised owner queue (`consume_async`, hard cap,
/// backpressure, timeout) without holding the entries lock or performing file
/// I/O on the async executor thread. No detached `spawn_blocking` flood.
pub struct AdmissionHandler<V> {
    validator: V,
    limiter: HandshakeAdmissionLimiter,
    replay_cache: Arc<ReplayCache>,
    sessions: Arc<V2SessionManager>,
    metrics: AdmissionMetrics,
}

impl<V: AdmissionTicketValidator> AdmissionHandler<V> {
    pub fn new(
        validator: V,
        limiter: HandshakeAdmissionLimiter,
        replay_cache: ReplayCache,
        sessions: Arc<V2SessionManager>,
    ) -> Self {
        Self {
            validator,
            limiter,
            replay_cache: Arc::new(replay_cache),
            sessions,
            metrics: AdmissionMetrics::default(),
        }
    }

    #[must_use]
    pub fn metrics(&self) -> AdmissionMetricsSnapshot {
        AdmissionMetricsSnapshot {
            admitted: self.metrics.admitted.load(Ordering::Relaxed),
            limiter_rejected: self.metrics.limiter_rejected.load(Ordering::Relaxed),
            ticket_rejected: self.metrics.ticket_rejected.load(Ordering::Relaxed),
            controller_unavailable: self.metrics.controller_unavailable.load(Ordering::Relaxed),
            provisioning_rejected: self.metrics.provisioning_rejected.load(Ordering::Relaxed),
            replay: self.replay_cache.snapshot(),
            limiter: self.limiter.snapshot(),
            sessions: self.sessions.snapshot(),
        }
    }

    pub(super) fn acquire_handshake(
        &self,
        source: IpAddr,
        now: AdmissionTime,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.limiter.acquire(source, now.monotonic_millis, now.monotonic_millis).map_err(|_| {
            self.metrics.limiter_rejected.fetch_add(1, Ordering::Relaxed);
            AdmissionError::Limited
        })
    }

    /// Production async admission for the V2 listener. Ticket validation and
    /// session reservation run inline (brief locks, no I/O); the durable
    /// replay consume runs on the supervised owner queue with
    /// [`REPLAY_JOURNAL_IO_TIMEOUT`] via `consume_async`, so this future
    /// never holds the replay entries lock and never performs file I/O on
    /// the async executor thread. A journal timeout/full/closed fails closed
    /// with [`AdmissionError::Unavailable`]. No lock is held across the await:
    /// the limiter permit owns only an `Arc` (no guard), and the session-map
    /// lock is acquired only inside the sync reservation after the await.
    pub(super) async fn admit_async(
        &self,
        source: IpAddr,
        peer: VerifiedPeer,
        hello: &BoundedClientHello,
        trust: Option<&ControllerTrustSnapshot>,
        started_at_monotonic_millis: u64,
        now: AdmissionTime,
    ) -> Result<AdmissionAccepted, AdmissionError> {
        let _permit = self
            .limiter
            .acquire(source, started_at_monotonic_millis, now.monotonic_millis)
            .map_err(|_| {
                self.metrics.limiter_rejected.fetch_add(1, Ordering::Relaxed);
                AdmissionError::Limited
            })?;
        let ticket = validate_admission_ticket(
            &self.validator,
            hello.ticket.as_str(),
            trust,
            now.unix_seconds,
            peer.0,
            hello.device_id,
        )
        .map_err(|error| {
            if error == TicketVerificationError::ControllerUnavailable {
                self.metrics.controller_unavailable.fetch_add(1, Ordering::Relaxed);
            } else {
                self.metrics.ticket_rejected.fetch_add(1, Ordering::Relaxed);
            }
            AdmissionError::Ticket(error)
        })?;
        Arc::clone(&self.replay_cache)
            .consume_async(ticket.ticket_id(), ticket.expires_at_unix_seconds(), now.unix_seconds)
            .await
            .map_err(|error| match error {
                ReplayCacheError::Replay => AdmissionError::Replay,
                ReplayCacheError::Capacity => AdmissionError::ReplayCapacity,
                ReplayCacheError::Unavailable => AdmissionError::Unavailable,
            })?;
        let owner = SessionOwner::from_ticket(&ticket);
        let expires_at_monotonic_ms = now
            .monotonic_millis
            .saturating_add(ticket.expires_at_unix_seconds().saturating_sub(now.unix_seconds).saturating_mul(1_000));
        let reservation = self
            .sessions
            .reserve_admission(
                owner.session_id(),
                owner.device_id(),
                owner.organization_id(),
                expires_at_monotonic_ms,
                now.monotonic_millis,
            )
            .map_err(|_| {
            self.metrics.provisioning_rejected.fetch_add(1, Ordering::Relaxed);
            AdmissionError::ProvisioningRejected
        })?;
        self.metrics.admitted.fetch_add(1, Ordering::Relaxed);
        Ok(AdmissionAccepted {
            owner,
            expires_at_unix_seconds: ticket.expires_at_unix_seconds(),
            policy_version: ticket.policy_version(),
            reservation,
        })
    }

    pub(super) fn commit_and_bind(
        &self,
        admitted: AdmissionAccepted,
        now: AdmissionTime,
    ) -> Result<AuthenticatedConnection, AdmissionError> {
        self.sessions
            .commit_admission_and_bind(admitted.reservation(), now.monotonic_millis)
            .map_err(|_| AdmissionError::ProvisioningRejected)
    }

    pub(super) fn abort(&self, admitted: AdmissionAccepted) {
        let _ = self.sessions.abort_admission(admitted.reservation());
    }

    pub(super) fn sweep(&self, now_ms: u64) -> Result<usize, V2SessionManagerError> {
        self.sessions.sweep(now_ms)
    }

    pub(super) fn reserve_attach(
        &self,
        connection: AuthenticatedConnection,
        path_epoch: u64,
        key_epoch: u32,
        now_ms: u64,
    ) -> Result<GatewayAttachReservation, V2SessionManagerError> {
        self.sessions.reserve_attach(connection, path_epoch, key_epoch, now_ms)
    }

    pub(super) fn commit_attach(
        &self,
        reservation: GatewayAttachReservation,
    ) -> Result<PathBinding, V2SessionManagerError> {
        self.sessions.commit_attach(reservation)
    }

    pub(super) fn detach_connection(
        &self,
        connection: AuthenticatedConnection,
        path_id: PathId,
        path_epoch: u64,
        now_ms: u64,
    ) -> Result<bool, V2SessionManagerError> {
        self.sessions.detach_connection(connection, path_id, path_epoch, now_ms)
    }

    pub(super) fn validate_attached_path(
        &self,
        connection: AuthenticatedConnection,
        path_id: PathId,
        path_epoch: u64,
        key_epoch: u32,
        now_ms: u64,
    ) -> Result<(), V2SessionManagerError> {
        self.sessions
            .validate_attached_path(connection, path_id, path_epoch, key_epoch, now_ms)
    }

    pub(super) fn record_authenticated_activity(
        &self,
        connection: AuthenticatedConnection,
        now_ms: u64,
    ) -> Result<(), V2SessionManagerError> {
        self.sessions.record_authenticated_activity(connection, now_ms)
    }

    pub(super) fn close_connection(
        &self,
        connection: AuthenticatedConnection,
    ) -> Result<bool, V2SessionManagerError> {
        self.sessions.close_connection(connection)
    }

    pub(super) fn close_session(
        &self,
        connection: AuthenticatedConnection,
    ) -> Result<bool, V2SessionManagerError> {
        self.sessions.close_session(connection)
    }

    /// Closes a session by its ID after its address lease expired. The
    /// listener calls this for every session ID returned by
    /// [`AddressPool::sweep`](crate::v2::address_pool::AddressPool::sweep) so
    /// an expired lease never leaves a live session without addresses.
    /// Idempotent: unknown sessions report `Ok(false)`. Cleanup (including
    /// the durable lease release) runs after the session-map lock via the
    /// registered [`SessionCleanup`](super::session_manager::SessionCleanup)
    /// hooks, so the call order is always session map then address pool.
    pub(crate) fn close_session_by_id(
        &self,
        session_id: SessionId,
    ) -> Result<bool, V2SessionManagerError> {
        self.sessions.close(session_id)
    }

    /// Closes the replay owner queue (no new persistence work) and joins the
    /// worker with the bounded shutdown deadline. Never hangs indefinitely.
    /// Idempotent. In-memory caches are a no-op.
    pub async fn stop_persistence(&self) -> Option<super::persistence::PersistenceSnapshot> {
        self.replay_cache.stop_persistence().await
    }
}

impl<V: fmt::Debug> fmt::Debug for AdmissionHandler<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionHandler(REDACTED)")
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("V2 admission configuration is invalid")]
    InvalidConfiguration,
    #[error("V2 ClientHello is invalid")]
    InvalidHello,
    #[error("V2 admission is rate limited")]
    Limited,
    #[error("V2 ticket admission failed")]
    Ticket(TicketVerificationError),
    #[error("V2 ticket replay was rejected")]
    Replay,
    #[error("V2 ticket replay cache is at capacity")]
    ReplayCapacity,
    #[error("V2 ticket redemption journal is unavailable")]
    ReplayStore,
    #[error("V2 admission state is unavailable")]
    Unavailable,
    #[error("V2 session owner provisioning rejected admission")]
    ProvisioningRejected,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionProvisioningError {
    #[error("V2 session owner is rejected")]
    OwnerRejected,
    #[error("V2 owner registry is at capacity")]
    Capacity,
    #[error("V2 owner registry is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    fn limiter() -> HandshakeAdmissionLimiter {
        HandshakeAdmissionLimiter::new(HandshakeAdmissionLimiterConfig {
            source_capacity: 2,
            source_ttl_millis: 10,
            maximum_per_source_in_flight: 1,
            maximum_global_in_flight: 2,
            maximum_verification_budget_millis: 5,
        })
        .unwrap()
    }

    #[test]
    fn replay_cache_is_atomic_bounded_and_reports_expiry() {
        let cache = Arc::new(ReplayCache::new(1).unwrap());
        assert_eq!(cache.consume(TicketId::from_bytes([1; 16]), 1, 1), Ok(()));
        assert_eq!(cache.consume(TicketId::from_bytes([1; 16]), 1, 1), Err(ReplayCacheError::Replay));
        assert_eq!(cache.consume(TicketId::from_bytes([2; 16]), 1, 1), Err(ReplayCacheError::Capacity));
        let concurrent = Arc::new(ReplayCache::new(2).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let other = Arc::clone(&concurrent);
        let other_barrier = Arc::clone(&barrier);
        let thread = thread::spawn(move || {
            other_barrier.wait();
            other.consume(TicketId::from_bytes([3; 16]), 100, 1)
        });
        barrier.wait();
        let first = concurrent.consume(TicketId::from_bytes([3; 16]), 100, 1);
        let second = thread.join().unwrap();
        assert_eq!([first, second].into_iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(cache.consume(TicketId::from_bytes([4; 16]), 1, 40), Ok(()));
        let snapshot = cache.snapshot();
        assert_eq!(snapshot.entries, 1);
        assert_eq!(snapshot.replay_rejected, 1);
        assert_eq!(snapshot.capacity_rejected, 1);
        assert_eq!(snapshot.expired, 1);
    }

    #[tokio::test]
    async fn durable_consume_async_is_time_bounded_and_shutdown_survives_blocked_journal() {
        // Blocked-journal shutdown proof: the first durable consume blocks in
        // the one-shot gate while holding the single entries lock on its
        // blocking thread. The async caller must fail closed via
        // `REPLAY_JOURNAL_IO_TIMEOUT` without holding any lock on its own
        // thread, and shutdown (drop plus a post-unblock consume) must complete
        // within hard deadlines. No sleep polling: `entered` plus completion
        // acks order every assertion.
        const OUTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let journal = std::env::temp_dir().join(format!("sg-replay-blocked-{nonce}.journal"));
        let _ = std::fs::remove_file(&journal);
        let cache = Arc::new(ReplayCache::open_durable(&journal, "blocked.test", 4, 1_000).unwrap());
        assert!(cache.is_durable());
        let (_gate, entered_rx, proceed_tx) = TestGate::install(&cache);

        // First consume blocks in the gate on its blocking thread.
        let blocked = Arc::clone(&cache);
        let blocked_task = tokio::spawn(async move {
            blocked.consume_async(TicketId::from_bytes([11; 16]), 2_000, 1_000).await
        });
        // Deterministic gate ack: the blocking thread reached the journal
        // rewrite while holding the entries lock. Wait off the executor so the
        // async listener thread never blocks.
        let entered_result = tokio::task::spawn_blocking(move || entered_rx.recv_timeout(OUTER_TIMEOUT))
            .await
            .expect("entered wait must join");
        assert!(entered_result.is_ok(), "blocked consume must reach the journal gate");

        // Time-bounded fail-closed: the async caller times out via
        // `REPLAY_JOURNAL_IO_TIMEOUT` (500 ms) even though the journal stays
        // blocked, returning `Unavailable` rather than hanging. The outer
        // timeout is only a hang backstop, not the assertion clock.
        let blocked_result = tokio::time::timeout(OUTER_TIMEOUT, blocked_task)
            .await
            .expect("blocked consume must complete via inner timeout, not hang")
            .expect("blocked task must join");
        assert_eq!(blocked_result, Err(ReplayCacheError::Unavailable));

        // Shutdown under blocked journal: dropping our handle while the
        // blocking write still holds the entries lock must not hang. The
        // background task holds its own `Arc` clone, so this drop is immediate;
        // the outer timeout proves no hang.
        let shutdown_cache = Arc::clone(&cache);
        tokio::time::timeout(OUTER_TIMEOUT, async move { drop(shutdown_cache) })
            .await
            .expect("shutdown drop under blocked journal must not hang");

        // Recovery: unblock the journal, then a fresh ticket must persist via
        // the bounded blocking pool with an ack, proving no poisoned lock and
        // no leaked serialization after the blocked episode.
        let _ = proceed_tx.send(());
        tokio::time::timeout(
            OUTER_TIMEOUT,
            Arc::clone(&cache).consume_async(TicketId::from_bytes([12; 16]), 2_000, 1_000),
        )
        .await
        .expect("post-unblock consume must complete, not hang")
        .expect("post-unblock consume must persist");
        // The unblocked first write eventually persisted its ticket (fail-closed
        // burn, not double-admit): a retry for the first ID is now `Replay`.
        // Wait for that persistence deterministically via a bounded retry loop
        // driven by completion acks, not sleeps: each attempt is itself
        // time-bounded, and the loop exits on the first `Replay`.
        let mut observed_replay = false;
        for _ in 0..20 {
            let attempt = tokio::time::timeout(
                OUTER_TIMEOUT,
                Arc::clone(&cache).consume_async(TicketId::from_bytes([11; 16]), 2_000, 1_000),
            )
            .await
            .expect("retry must complete")
            .expect_err("retry must fail (Replay or Unavailable while persisting)");
            if attempt == ReplayCacheError::Replay {
                observed_replay = true;
                break;
            }
        }
        assert!(observed_replay, "blocked ticket must persist as consumed after unblock");
        let _ = std::fs::remove_file(&journal);
        let _ = std::fs::remove_file(journal.with_extension("tmp"));
    }

    #[tokio::test]
    async fn durable_consume_async_persists_without_blocking_the_listener() {
        // Healthy durable path: `consume_async` runs the single-guard rewrite
        // on the bounded blocking pool and returns `Ok`, with the journal file
        // present for reopen. The listener never holds the entries lock across
        // this await (the lock lives only on the blocking thread).
        const OUTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let journal = std::env::temp_dir().join(format!("sg-replay-healthy-{nonce}.journal"));
        let _ = std::fs::remove_file(&journal);
        let cache = Arc::new(ReplayCache::open_durable(&journal, "healthy.test", 4, 1_000).unwrap());
        tokio::time::timeout(
            OUTER_TIMEOUT,
            Arc::clone(&cache).consume_async(TicketId::from_bytes([21; 16]), 2_000, 1_000),
        )
        .await
        .expect("healthy consume must complete")
        .expect("healthy consume must persist");
        assert_eq!(cache.snapshot().entries, 1);
        drop(cache);
        let reopened = ReplayCache::open_durable(&journal, "healthy.test", 4, 1_000).unwrap();
        assert_eq!(reopened.snapshot().entries, 1);
        let _ = std::fs::remove_file(&journal);
        let _ = std::fs::remove_file(journal.with_extension("tmp"));
    }

    #[test]
    fn limiter_enforces_pre_handshake_capacity_ttl_deadline_and_raii_release() {
        let limiter = limiter();
        let first = limiter.acquire("192.0.2.1".parse().unwrap(), 0, 0).unwrap();
        assert!(matches!(limiter.acquire("192.0.2.1".parse().unwrap(), 0, 0), Err(LimiterError::SourceInFlight)));
        let second = limiter.acquire("192.0.2.2".parse().unwrap(), 0, 0).unwrap();
        assert!(matches!(limiter.acquire("192.0.2.3".parse().unwrap(), 0, 0), Err(LimiterError::GlobalInFlight)));
        drop(first);
        drop(second);
        assert!(limiter.acquire("192.0.2.3".parse().unwrap(), 11, 11).is_ok());
        assert!(matches!(limiter.acquire("192.0.2.4".parse().unwrap(), 0, 6), Err(LimiterError::BudgetExceeded)));
        let source_limiter = HandshakeAdmissionLimiter::new(HandshakeAdmissionLimiterConfig {
            source_capacity: 1,
            source_ttl_millis: 10,
            maximum_per_source_in_flight: 1,
            maximum_global_in_flight: 2,
            maximum_verification_budget_millis: 5,
        })
        .unwrap();
        assert!(source_limiter.acquire("192.0.2.20".parse().unwrap(), 0, 0).is_ok());
        assert!(matches!(source_limiter.acquire("192.0.2.21".parse().unwrap(), 0, 0), Err(LimiterError::SourceCapacity)));
        assert!(source_limiter.acquire("192.0.2.21".parse().unwrap(), 11, 11).is_ok());
        let snapshot = source_limiter.snapshot();
        assert_eq!(snapshot.source_capacity_rejected, 1);
        assert_eq!(snapshot.expired, 1);
    }
}
