//! Bounded V2 ticket admission and minimal owner registry.
//!
//! This module has no V1 session, path, TUN, payload, or flow dependency.
//! WP-202 owns the real V2 session/path lifecycle; this registry only proves
//! that no owner is allocated before mTLS and ticket admission succeed.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sg_auth::device::{AdmissionTicketValidator, validate_admission_ticket};
use sg_auth::ticket::{
    ControllerTrustSnapshot, OrganizationId, REPLAY_EXPIRY_SKEW_SECONDS, TicketId,
    TicketVerificationError, VerifiedAdmissionTicket,
};
use sg_core::v2::{DeviceId, SessionId};
use sg_protocol::v2::control::{AdmissionTicket, ControlMessage, MAX_GATEWAY_NAME_LEN};
use thiserror::Error;

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

/// Gateway-loop time is supplied by the caller so resource policy is
/// deterministic and admission never needs a timer task.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionOwnerRegistryConfig {
    pub capacity: usize,
    pub ttl_seconds: u64,
}

/// The intentionally narrow pre-WP-202 owner registry. Entries are bounded
/// and expire; a later ticket may only reuse a full session ID for the exact
/// same device and organization. It has no paths or packet state.
pub struct AdmissionOwnerRegistry {
    config: AdmissionOwnerRegistryConfig,
    entries: Mutex<HashMap<SessionId, OwnerEntry>>,
    capacity_rejected: AtomicU64,
    owner_rejected: AtomicU64,
    expired: AtomicU64,
}

struct OwnerEntry {
    owner: SessionOwner,
    expires_at_unix_seconds: u64,
}

impl AdmissionOwnerRegistry {
    pub fn new(config: AdmissionOwnerRegistryConfig) -> Result<Self, AdmissionError> {
        if config.capacity == 0 || config.ttl_seconds == 0 {
            return Err(AdmissionError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            entries: Mutex::new(HashMap::new()),
            capacity_rejected: AtomicU64::new(0),
            owner_rejected: AtomicU64::new(0),
            expired: AtomicU64::new(0),
        })
    }

    fn provision(
        &self,
        owner: SessionOwner,
        ticket: &VerifiedAdmissionTicket,
        now_unix_seconds: u64,
    ) -> Result<(), AdmissionProvisioningError> {
        let mut entries = self.entries.lock().map_err(|_| AdmissionProvisioningError::Unavailable)?;
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at_unix_seconds > now_unix_seconds);
        self.expired.fetch_add((before - entries.len()) as u64, Ordering::Relaxed);

        let expires_at_unix_seconds = ticket
            .expires_at_unix_seconds()
            .min(now_unix_seconds.saturating_add(self.config.ttl_seconds));
        if let Some(entry) = entries.get_mut(&owner.session_id()) {
            if entry.owner != owner {
                self.owner_rejected.fetch_add(1, Ordering::Relaxed);
                return Err(AdmissionProvisioningError::OwnerRejected);
            }
            entry.expires_at_unix_seconds = entry.expires_at_unix_seconds.max(expires_at_unix_seconds);
            return Ok(());
        }
        if entries.len() >= self.config.capacity {
            self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(AdmissionProvisioningError::Capacity);
        }
        entries.insert(owner.session_id(), OwnerEntry { owner, expires_at_unix_seconds });
        Ok(())
    }

    #[must_use]
    pub fn snapshot(&self) -> AdmissionOwnerRegistrySnapshot {
        let entries = self.entries.lock().map(|entries| entries.len()).unwrap_or(0);
        AdmissionOwnerRegistrySnapshot {
            entries,
            capacity: self.config.capacity,
            capacity_rejected: self.capacity_rejected.load(Ordering::Relaxed),
            owner_rejected: self.owner_rejected.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
        }
    }
}

impl fmt::Debug for AdmissionOwnerRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionOwnerRegistry(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionOwnerRegistrySnapshot {
    pub entries: usize,
    pub capacity: usize,
    pub capacity_rejected: u64,
    pub owner_rejected: u64,
    pub expired: u64,
}

/// Successful verification data used by the listener's SessionAdmit builder.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdmissionAccepted {
    owner: SessionOwner,
    expires_at_unix_seconds: u64,
    policy_version: u64,
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
}

impl fmt::Debug for AdmissionAccepted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionAccepted(REDACTED)")
    }
}

/// A bounded, atomic, fail-closed replay cache. Live entries are never evicted
/// for capacity; only expiry plus fixed skew permits removal.
pub struct ReplayCache {
    capacity: usize,
    entries: Mutex<BTreeMap<TicketId, u64>>,
    replay_rejected: AtomicU64,
    capacity_rejected: AtomicU64,
    expired: AtomicU64,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Result<Self, AdmissionError> {
        if capacity == 0 {
            return Err(AdmissionError::InvalidConfiguration);
        }
        Ok(Self {
            capacity,
            entries: Mutex::new(BTreeMap::new()),
            replay_rejected: AtomicU64::new(0),
            capacity_rejected: AtomicU64::new(0),
            expired: AtomicU64::new(0),
        })
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
        Ok(())
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
    pub owners: AdmissionOwnerRegistrySnapshot,
}

/// Ticket admission is deliberately crate-private. The only public ingress is
/// the V2 listener, which creates `VerifiedPeer` from Quinn's verified chain.
pub struct AdmissionHandler<V> {
    validator: V,
    limiter: HandshakeAdmissionLimiter,
    replay_cache: ReplayCache,
    owners: AdmissionOwnerRegistry,
    metrics: AdmissionMetrics,
}

impl<V: AdmissionTicketValidator> AdmissionHandler<V> {
    pub fn new(
        validator: V,
        limiter: HandshakeAdmissionLimiter,
        replay_cache: ReplayCache,
        owners: AdmissionOwnerRegistry,
    ) -> Self {
        Self { validator, limiter, replay_cache, owners, metrics: AdmissionMetrics::default() }
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
            owners: self.owners.snapshot(),
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

    pub(super) fn admit(
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
        self.replay_cache
            .consume(ticket.ticket_id(), ticket.expires_at_unix_seconds(), now.unix_seconds)
            .map_err(|error| match error {
                ReplayCacheError::Replay => AdmissionError::Replay,
                ReplayCacheError::Capacity => AdmissionError::ReplayCapacity,
                ReplayCacheError::Unavailable => AdmissionError::Unavailable,
            })?;
        let owner = SessionOwner::from_ticket(&ticket);
        self.owners.provision(owner, &ticket, now.unix_seconds).map_err(|_| {
            self.metrics.provisioning_rejected.fetch_add(1, Ordering::Relaxed);
            AdmissionError::ProvisioningRejected
        })?;
        self.metrics.admitted.fetch_add(1, Ordering::Relaxed);
        Ok(AdmissionAccepted {
            owner,
            expires_at_unix_seconds: ticket.expires_at_unix_seconds(),
            policy_version: ticket.policy_version(),
        })
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
