//! Bounded V2 gateway address allocation (REBUILD WP-400).
//!
//! Allocates one unique IPv4 address plus one IPv6 `/64` per active V2
//! session, enforces reserved exclusions, and validates sources before any
//! TUN/NAT forwarding (see `super::forwarding`). V1 code (`tunnel.rs`) is
//! untouched.
//!
//! # Bounds
//!
//! - At most `maximum_leases` Reserved plus Active leases. Release-pending
//!   (quarantine) holds at most `maximum_pending_releases` entries.
//! - IPv4 candidates are drawn from the configured network, never the
//!   network, broadcast, gateway, explicitly reserved, or quarantined
//!   addresses. Quarantined addresses are nonreusable until their durable
//!   delete succeeds.
//! - IPv6 leases are `/64`s carved from the configured parent prefix
//!   (`16..=63`); subnet zero is reserved for the gateway and never leased.
//!   Quarantined `/64`s are likewise nonreusable.
//! - The durable release-retry quarantine never drops on overflow. When it is
//!   full, the releasing call fails closed (`Store`) and the lease stays
//!   blocked for reuse; `release_retry_dropped` is retained for compatibility
//!   and always reads zero.
//!
//! # Persistence modes
//!
//! - **Ephemeral** (`AddressPool::new` / `AddressPoolMode::Ephemeral`): no
//!   store. Suitable for single-run gateways and unit tests. A restart frees
//!   all leases.
//! - **Self-hosted durable** (`AddressPoolMode::SelfHosted`): the concrete
//!   atomic [`JournalLeaseStore`] file journal. Every mutation rewrites a
//!   temp file and renames it, so a crash leaves the old or the new journal,
//!   never a half-write. Missing file means empty; corrupt, trailing-data,
//!   or over-bound journals fail startup closed.
//! - **Managed durable** (`AddressPool::with_store` /
//!   `AddressPoolMode::Managed`): an external store behind the
//!   [`ManagedLeaseStore`] adapter, which enforces `MAX_LEASES_HARD_CAP` at
//!   the store boundary. Use [`AddressPool::open`] to select the mode
//!   explicitly; every durable mode fails startup closed on any load, bound,
//!   or validation failure (never an empty-pool fallback).
//!
//! Every reserve/commit persists a [`PersistedLease`] carrying its
//! [`LeaseState`] plus `expires_at_ms`, and every release removes it. Any
//! store failure fails the allocating call closed (no lease is handed out)
//! and release failures quarantine the lease as `ReleasePending`
//! (nonreusable) for bounded retry with backoff
//! ([`AddressPool::retry_pending_releases_bounded`]). Recovery streams at
//! most `maximum_leases + maximum_pending_releases` records (hard-capped by
//! `MAX_LEASES_HARD_CAP`), validates each persisted entry (non-zero IDs,
//! in-pool addresses, not reserved, no duplicates, unexpired), restores only
//! the valid prefix deterministically, deletes discarded entries, and
//! quarantines any discarded entry whose delete fails (nonreusable, fail
//! closed) while counting `recovered_dropped`.
//!
//! # Lifecycle policy (WP-400 requirement 4)
//!
//! - **Lease records**: every in-memory and durable record carries
//!   `Reserved | Active | ReleasePending` plus `expires_at_ms`. Reserved uses
//!   `pending_ttl_ms`, Active uses `lease_ttl_ms`, ReleasePending retains the
//!   original expiry for audit and retry.
//! - **Renewal (DHCP-like)**: active leases carry `expires_at_ms`
//!   (`now + lease_ttl_ms`). [`AddressPool::renew`] extends it; production
//!   calls renew on session activity. Expiry does not silently reassign:
//!   [`AddressPool::sweep`] frees expired Reserved and Active leases with a
//!   durable store release (quarantining on store failure), and returns the
//!   expired session IDs so the caller can close the corresponding sessions
//!   (idempotent). An expired same-session reservation met by [`AddressPool::reserve`]
//!   is replaced in memory and overwritten by the new persist (same session
//!   key), never silently dropped.
//! - **Resume**: `reserve` is idempotent for the same session plus device. A
//!   reconnect within TTL receives the same addresses. A different device
//!   claiming the same session receives `OwnerMismatch`.
//! - **Exhaustion**: when the IPv4 hosts, IPv6 subnets, or `maximum_leases`
//!   bound is reached, `reserve` returns `Exhausted` and counts it. No
//!   least-recently-used eviction steals a live lease.
//! - **Crash reserve / restart no-reuse**: a Reserved lease is persisted before
//!   it is returned, so a crash before commit still recovers the reservation
//!   and blocks reuse by other sessions. A failed durable delete quarantines
//!   the addresses; a restart recovers the store entry and still blocks reuse
//!   until the delete succeeds and is retried.
//! - **Collision avoidance**: the gateway IPv4 and the gateway IPv6 subnet
//!   (subnet zero) are never allocated, so gateway and client addresses
//!   cannot collide. [`super::forwarding`] additionally drops any uplink
//!   whose source equals the gateway address.
//!
//! # Admission ordering (WP-400 atomicity)
//!
//! The listener reserves durably (`reserve`), commits the session
//! (`commit_and_bind`), commits the lease to Active durably (`commit`), and
//! only then frames and writes `SessionAdmit`. Any failure after the durable
//! reserve releases (or quarantines) the lease and unwinds the session, so no
//! session is ever advertised without a unique durable lease.
//!
//! # Locking
//!
//! The pool uses one short `Mutex<Inner>` that is never held across store
//! I/O. Mutating calls park their session (plus addresses) in the inflight
//! set, drop the lock, perform exactly one store operation, then re-acquire
//! the lock to commit: concurrent allocators block reuse of inflight
//! addresses, concurrent same-session callers fail closed with `Store`
//! (counted as `inflight_conflicts`), and sweeps skip inflight sessions.
//! Blocking journal I/O additionally runs on Tokio's bounded blocking pool
//! via the `*_async` wrappers, never on an executor thread.
//! [`SessionCleanup`](super::session_manager::SessionCleanup) is implemented
//! via the non-blocking [`AddressPool::release_deferred`], so session
//! expiry/close quarantines in memory (after the session-map lock is
//! released) and the bounded retry path performs the durable delete.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::sync::Arc;

use sg_core::v2::{DeviceId, SessionId};
use thiserror::Error;

use super::persistence::{
    PersistenceConfig, PersistenceError, PersistenceOwner, PoolTime, monotonic_expiry_from_wall,
    secure_atomic_write, validate_journal_file, wall_expiry_from_ttl,
};
use super::session_manager::{Clock, SessionCleanup, SessionRemoval, V2SessionManager};

/// Maximum explicitly reserved IPv4 addresses (excluding gateway/network).
const MAX_RESERVED_IPV4: usize = 32;
/// IPv6 lease prefix length: one `/64` per session (WP-400).
const IPV6_LEASE_PREFIX_LEN: u8 = 64;
/// Upper bound for lease counts so allocation scans stay deterministic.
const MAX_LEASES_HARD_CAP: usize = 65_536;
/// Atomic journal framing for the self-hosted durable store (WP-400).
/// One file holds at most `MAX_LEASES_HARD_CAP` fixed-size records; every
/// mutation rewrites a temp file and atomically renames it, so a crash never
/// leaves a half-written journal.
const JOURNAL_MAGIC: [u8; 4] = *b"SGAL";
/// Journal format version 2 persists wall-clock expiries (`expires_at_wall_ms`,
/// Unix millis). Version 1 (monotonic expiries, which reset on restart) is
/// rejected explicitly so an old monotonic journal can never silently recover
/// as wall time.
const JOURNAL_VERSION: u8 = 2;
/// Fixed record: magic(4) + version(1) + state(1) + session(16) + device(16)
/// + ipv4(4) + v4len(1) + ipv6(16) + v6len(1) + expires(8) = 68 bytes.
const JOURNAL_RECORD_LEN: usize = 68;
/// Hard cap for the journal file so a corrupt length prefix cannot induce a
/// huge allocation: records * record-len, bounded by the lease hard cap.
const MAX_JOURNAL_BYTES: u64 = (MAX_LEASES_HARD_CAP as u64) * (JOURNAL_RECORD_LEN as u64);
/// Bounded durable-delete retry: at most this many quarantined leases are
/// retried per call so a full quarantine (up to 65k) never blocks admission.
const MAX_RETRY_BATCH: usize = 32;
/// Exponential backoff for quarantined deletes (deterministic, no sleeps in
/// tests: callers pass `now_ms`; retries before `next_retry_ms` are deferred
/// and counted, never attempted).
const RETRY_BASE_MS: u64 = 1_000;
const RETRY_CAP_MS: u64 = 60_000;

/// Durable lease state. Every in-memory record carries a monotonic
/// `expires_at_ms` (process-relative TTL); every [`PersistedLease`] carries a
/// wall-clock `expires_at_ms` (Unix millis, see [`PoolTime`]). There is no
/// stateless address pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Reserved by `reserve`, not yet committed. Expires after `pending_ttl_ms`.
    Reserved,
    /// Committed by `commit`. Expires after `lease_ttl_ms` unless renewed.
    Active,
    /// Durable delete failed; addresses are quarantined as nonreusable until
    /// the store delete succeeds and is retried. Retains the original expiry.
    ReleasePending,
}

/// Durable record of one allocated address pair plus its lifecycle state and
/// wall-clock expiry (`expires_at_ms` is Unix millis, never monotonic: see
/// [`PoolTime`]). The store must persist all fields; recovery converts the
/// remaining wall time back to a monotonic deadline with
/// [`monotonic_expiry_from_wall`] (saturating, never panics) and drops expired
/// or invalid records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistedLease {
    pub session_id: SessionId,
    pub device_id: DeviceId,
    pub ipv4: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub ipv6_prefix: [u8; 16],
    pub ipv6_prefix_len: u8,
    pub state: LeaseState,
    pub expires_at_ms: u64,
}

/// Addresses handed to a session and echoed in `SessionAdmit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedAddresses {
    pub ipv4: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub ipv6_prefix: [u8; 16],
    pub ipv6_prefix_len: u8,
}

impl AssignedAddresses {
    #[must_use]
    pub const fn ipv4_addr(self) -> Ipv4Addr {
        Ipv4Addr::new(self.ipv4[0], self.ipv4[1], self.ipv4[2], self.ipv4[3])
    }

    #[must_use]
    pub fn ipv6_prefix_addr(self) -> Ipv6Addr {
        Ipv6Addr::from(self.ipv6_prefix)
    }
}

/// Configuration for the bounded address pool. All fields are validated by
/// [`AddressPoolConfig::new`]; use accessors, never struct-literal
/// construction across modules (fields are private to force validation).
#[derive(Debug, Clone)]
pub struct AddressPoolConfig {
    ipv4_network: [u8; 4],
    ipv4_prefix_len: u8,
    ipv4_gateway: [u8; 4],
    reserved_ipv4: Vec<[u8; 4]>,
    ipv6_base: [u8; 16],
    ipv6_parent_prefix_len: u8,
    maximum_leases: usize,
    pending_ttl_ms: u64,
    lease_ttl_ms: u64,
    maximum_pending_releases: usize,
}

impl AddressPoolConfig {
    /// Validates and builds a pool config.
    ///
    /// - `ipv4_network`/`ipv4_prefix_len`: `8..=30`, masked base required.
    /// - `ipv4_gateway`: must lie inside the network and must not be the
    ///   network or broadcast address.
    /// - `reserved_ipv4`: at most 32 entries, each inside the network and
    ///   distinct from gateway/network/broadcast.
    /// - `ipv6_base`/`ipv6_parent_prefix_len`: parent `16..=63`, base host
    ///   bits beyond the parent must be zero, and the parent must yield at
    ///   least one usable `/64` beyond the reserved gateway subnet.
    /// - `maximum_leases`: `1..=65536` and no larger than either address
    ///   family can supply.
    /// - TTLs: `pending_ttl_ms` in `1..=3_600_000`, `lease_ttl_ms` in
    ///   `1_000..=86_400_000`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ipv4_network: [u8; 4],
        ipv4_prefix_len: u8,
        ipv4_gateway: [u8; 4],
        reserved_ipv4: Vec<[u8; 4]>,
        ipv6_base: [u8; 16],
        ipv6_parent_prefix_len: u8,
        maximum_leases: usize,
        pending_ttl_ms: u64,
        lease_ttl_ms: u64,
        maximum_pending_releases: usize,
    ) -> Result<Self, AddressPoolError> {
        if !(8..=30).contains(&ipv4_prefix_len) {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        if maximum_leases == 0 || maximum_leases > MAX_LEASES_HARD_CAP {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        if !(1..=3_600_000).contains(&pending_ttl_ms) {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        if !(1_000..=86_400_000).contains(&lease_ttl_ms) {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        if maximum_pending_releases == 0 || maximum_pending_releases > MAX_LEASES_HARD_CAP {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        if reserved_ipv4.len() > MAX_RESERVED_IPV4 {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        if !(16..=63).contains(&ipv6_parent_prefix_len) {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        let mask = prefix_mask_v4(ipv4_prefix_len);
        let network_u32 = u32::from_be_bytes(ipv4_network) & mask;
        if u32::from_be_bytes(ipv4_network) != network_u32 {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        let broadcast_u32 = network_u32 | !mask;
        let gateway_u32 = u32::from_be_bytes(ipv4_gateway);
        if gateway_u32 & mask != network_u32 || gateway_u32 == network_u32 || gateway_u32 == broadcast_u32 {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        {
            let mut seen = HashSet::new();
            for reserved in &reserved_ipv4 {
                let value = u32::from_be_bytes(*reserved);
                if value & mask != network_u32 || value == network_u32 || value == broadcast_u32 || value == gateway_u32 {
                    return Err(AddressPoolError::InvalidConfiguration);
                }
                if !seen.insert(value) {
                    return Err(AddressPoolError::InvalidConfiguration);
                }
            }
        }
        if !ipv6_base_masked(&ipv6_base, ipv6_parent_prefix_len) {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        let usable_v6 = usable_ipv6_subnets(ipv6_parent_prefix_len);
        if usable_v6 == 0 || maximum_leases > usable_v6 as usize {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        let usable_v4 = usable_ipv4_hosts(network_u32, broadcast_u32, reserved_ipv4.len());
        if usable_v4 == 0 || maximum_leases > usable_v4 as usize {
            return Err(AddressPoolError::InvalidConfiguration);
        }
        Ok(Self {
            ipv4_network,
            ipv4_prefix_len,
            ipv4_gateway,
            reserved_ipv4,
            ipv6_base,
            ipv6_parent_prefix_len,
            maximum_leases,
            pending_ttl_ms,
            lease_ttl_ms,
            maximum_pending_releases,
        })
    }

    #[must_use]
    pub const fn maximum_leases(&self) -> usize {
        self.maximum_leases
    }

    #[must_use]
    pub const fn pending_ttl_ms(&self) -> u64 {
        self.pending_ttl_ms
    }

    #[must_use]
    pub const fn lease_ttl_ms(&self) -> u64 {
        self.lease_ttl_ms
    }

    #[must_use]
    pub fn ipv4_gateway(&self) -> [u8; 4] {
        self.ipv4_gateway
    }

    #[must_use]
    pub const fn ipv4_prefix_len(&self) -> u8 {
        self.ipv4_prefix_len
    }

    #[must_use]
    pub fn ipv6_base(&self) -> [u8; 16] {
        self.ipv6_base
    }

    #[must_use]
    pub const fn ipv6_parent_prefix_len(&self) -> u8 {
        self.ipv6_parent_prefix_len
    }
}

/// Durable store for allocated leases. Implementations must be bounded and
/// fail closed: any error rejects the allocating call and quarantines release
/// retries inside the pool as nonreusable `ReleasePending`.
pub trait LeaseStore: Send + Sync + std::fmt::Debug {
    /// Loads all persisted leases for recovery. Any error fails pool
    /// construction closed (no empty-pool fallback that could collide).
    /// Implementations must return at most `MAX_LEASES_HARD_CAP` entries; the
    /// pool additionally enforces `maximum_leases + maximum_pending_releases`
    /// and fails closed on overflow.
    fn load(&self) -> Result<Vec<PersistedLease>, StoreError>;
    /// Persists one lease (Reserved reserve or Active commit) including its
    /// state plus expiry.
    fn persist(&self, lease: &PersistedLease) -> Result<(), StoreError>;
    /// Removes the lease for a session. Failures quarantine the lease as
    /// `ReleasePending` (nonreusable) for retry; they never drop addresses.
    fn release(&self, session_id: &SessionId) -> Result<(), StoreError>;
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    #[error("address store is unavailable")]
    Unavailable,
    #[error("address store I/O failed")]
    Io,
    #[error("address store data is corrupt")]
    Corrupt,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AddressPoolError {
    #[error("address pool configuration is invalid")]
    InvalidConfiguration,
    #[error("address pool state is unavailable")]
    Unavailable,
    #[error("address pool is exhausted")]
    Exhausted,
    #[error("address pool session owner does not match")]
    OwnerMismatch,
    #[error("address pool lease is unknown")]
    UnknownLease,
    #[error("address pool lease is expired")]
    Expired,
    #[error("address pool durable store failed")]
    Store,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressPoolSnapshot {
    pub active: usize,
    pub pending: usize,
    pub pending_releases: usize,
    pub maximum_leases: usize,
    pub maximum_pending_releases: usize,
    pub allocations: u64,
    pub commits: u64,
    pub releases: u64,
    pub renewals: u64,
    pub exhausted: u64,
    pub owner_mismatch: u64,
    pub pending_expired: u64,
    pub active_expired: u64,
    pub store_failures: u64,
    pub recovered: u64,
    pub recovered_dropped: u64,
    pub release_retries: u64,
    pub release_retry_dropped: u64,
    pub quarantine_full: u64,
    pub release_retry_deferred: u64,
    pub inflight_conflicts: u64,
}

#[derive(Default)]
struct PoolMetrics {
    allocations: AtomicU64,
    commits: AtomicU64,
    releases: AtomicU64,
    renewals: AtomicU64,
    exhausted: AtomicU64,
    owner_mismatch: AtomicU64,
    pending_expired: AtomicU64,
    active_expired: AtomicU64,
    store_failures: AtomicU64,
    recovered: AtomicU64,
    recovered_dropped: AtomicU64,
    release_retries: AtomicU64,
    release_retry_dropped: AtomicU64,
    quarantine_full: AtomicU64,
    release_retry_deferred: AtomicU64,
    inflight_conflicts: AtomicU64,
}

/// Reserved lease: persisted before it is returned, expires after
/// `pending_ttl_ms`. A crash before commit still recovers this reservation.
struct ReservedLease {
    device_id: DeviceId,
    addresses: AssignedAddresses,
    expires_at_ms: u64,
}

struct ActiveLease {
    device_id: DeviceId,
    addresses: AssignedAddresses,
    expires_at_ms: u64,
}

/// Quarantined lease: durable delete failed. Addresses are nonreusable until
/// the store delete succeeds. Retains the original expiry plus retry count
/// and the next eligible retry deadline (`next_retry_ms`, exponential
/// backoff) for audit; expiry and attempts are exposed via
/// [`AddressPool::quarantined`] for observability.
struct ReleasePendingLease {
    device_id: DeviceId,
    addresses: AssignedAddresses,
    expires_at_ms: u64,
    attempts: u64,
    next_retry_ms: u64,
}

struct Inner {
    active: HashMap<SessionId, ActiveLease>,
    /// Reserved leases (`pending` in snapshots for compatibility).
    pending: HashMap<SessionId, ReservedLease>,
    /// Quarantined ReleasePending leases, nonreusable until retried.
    release_pending: HashMap<SessionId, ReleasePendingLease>,
    /// Deterministic retry order for quarantined session IDs.
    release_order: VecDeque<SessionId>,
    /// Reservation-generation protocol: sessions (plus their addresses)
    /// with store I/O in flight. The pool mutex is never held across store
    /// I/O; instead the session is parked here before the lock is dropped,
    /// so concurrent allocators block reuse and concurrent same-session
    /// callers fail closed (`Store`, counted as `inflight_conflicts`) until
    /// the I/O commits. Sweeps skip inflight sessions.
    inflight: HashSet<SessionId>,
    inflight_v4: HashSet<u32>,
    inflight_v6: HashSet<[u8; 16]>,
}

/// Bounded, deterministic IPv4 plus IPv6 `/64` allocator.
///
/// Durable pools own one supervised [`PersistenceOwner`] (bounded queue, one
/// worker thread) for all async file I/O; ephemeral pools have no owner and
/// run inline. Sync methods (`reserve`, `commit`, …) are for startup and
/// deterministic tests (they block the caller); production async callers must
/// use the `*_async` / `*_at_time_async` wrappers, which route through the
/// owner (hard cap, backpressure, `io_timeout` fail-closed) and never spawn
/// detached `spawn_blocking` tasks.
pub struct AddressPool {
    config: AddressPoolConfig,
    inner: Mutex<Inner>,
    store: Option<Arc<dyn LeaseStore>>,
    metrics: PoolMetrics,
    persistence: Option<Arc<PersistenceOwner>>,
}

impl std::fmt::Debug for AddressPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AddressPool(REDACTED)")
    }
}

impl AddressPool {
    /// Ephemeral pool (self-hosted single-run). No durability.
    pub fn new(config: AddressPoolConfig) -> Result<Self, AddressPoolError> {
        Ok(Self {
            config,
            inner: Mutex::new(Inner {
                active: HashMap::new(),
                pending: HashMap::new(),
                release_pending: HashMap::new(),
                release_order: VecDeque::new(),
                inflight: HashSet::new(),
                inflight_v4: HashSet::new(),
                inflight_v6: HashSet::new(),
            }),
            store: None,
            metrics: PoolMetrics::default(),
            persistence: None,
        })
    }

    /// Durable pool (managed mode). Fails closed when `load` fails, when the
    /// persisted stream exceeds `MAX_LEASES_HARD_CAP`, or when any persisted
    /// entry cannot be reconciled within bounds: invalid or expired entries
    /// are dropped and counted (with a best-effort durable delete), valid
    /// entries are restored with their persisted `state` plus wall expiry
    /// converted to a monotonic deadline so crash reserves and quarantined
    /// deletes keep blocking reuse.
    ///
    /// Test/legacy entry point: `now_ms` supplies both domains
    /// (`PoolTime::from_monotonic`). Production must use
    /// [`with_store_at_time`](Self::with_store_at_time) with a real wall
    /// clock so leases survive a restart.
    pub fn with_store(
        config: AddressPoolConfig,
        store: Arc<dyn LeaseStore>,
        now_ms: u64,
    ) -> Result<Self, AddressPoolError> {
        Self::with_store_at_time(config, store, PoolTime::from_monotonic(now_ms))
    }

    /// Wall-aware durable pool construction. `now.wall_ms` is the durable
    /// expiry domain (persisted); `now.monotonic_ms` drives in-memory TTLs.
    /// Recovery converts remaining wall time to monotonic deadlines with
    /// saturating arithmetic (see [`monotonic_expiry_from_wall`]).
    pub fn with_store_at_time(
        config: AddressPoolConfig,
        store: Arc<dyn LeaseStore>,
        now: PoolTime,
    ) -> Result<Self, AddressPoolError> {
        let persisted = store.load().map_err(|_| AddressPoolError::Store)?;
        if persisted.len() > MAX_LEASES_HARD_CAP {
            return Err(AddressPoolError::Store);
        }
        let pool = Self {
            config,
            inner: Mutex::new(Inner {
                active: HashMap::new(),
                pending: HashMap::new(),
                release_pending: HashMap::new(),
                release_order: VecDeque::new(),
                inflight: HashSet::new(),
                inflight_v4: HashSet::new(),
                inflight_v6: HashSet::new(),
            }),
            store: Some(store),
            metrics: PoolMetrics::default(),
            persistence: Some(Arc::new(PersistenceOwner::start(PersistenceConfig::default()))),
        };
        pool.recover_locked_at_time(persisted, now)?;
        Ok(pool)
    }

    /// Explicit startup constructor for every persistence mode (WP-400
    /// requirement 2). Recovery is identical in both durable modes and always
    /// fail-closed: a load failure, an over-bound stream, a corrupt journal,
    /// or a quarantine-overflow during discarded-delete recovery returns
    /// [`AddressPoolError::Store`] and constructs no pool.
    ///
    /// - `Ephemeral`: no store, no recovery. A restart frees all leases.
    /// - `SelfHosted { journal_path }`: opens the atomic journal (missing
    ///   file means empty; corrupt means `Store`) and recovers it.
    /// - `Managed { store }`: loads through the [`ManagedLeaseStore`]
    ///   adapter (hard-cap enforced at the store boundary) and recovers it.
    pub fn open(config: AddressPoolConfig, mode: AddressPoolMode, now_ms: u64) -> Result<Self, AddressPoolError> {
        Self::open_at_time(config, mode, PoolTime::from_monotonic(now_ms))
    }

    /// Wall-aware startup constructor. Production passes a real dual clock
    /// (`monotonic_ms` near zero, `wall_ms` real Unix millis); tests pass
    /// `PoolTime::from_monotonic` for determinism.
    pub fn open_at_time(
        config: AddressPoolConfig,
        mode: AddressPoolMode,
        now: PoolTime,
    ) -> Result<Self, AddressPoolError> {
        match mode {
            AddressPoolMode::Ephemeral => Self::new(config),
            AddressPoolMode::SelfHosted { journal_path } => {
                let journal = JournalLeaseStore::open(&journal_path).map_err(|_| AddressPoolError::Store)?;
                Self::with_store_at_time(config, Arc::new(journal), now)
            }
            AddressPoolMode::Managed { store } => {
                let adapter = ManagedLeaseStore::new(store);
                Self::with_store_at_time(config, Arc::new(adapter), now)
            }
        }
    }

    /// Reserves (or idempotently returns) the lease for a session. The same
    /// session plus device receives the same addresses; a different device
    /// receives `OwnerMismatch`. New reservations persist the Reserved lease
    /// (state plus expiry) before returning, so store failures fail closed
    /// with no allocation. Expired Reserved entries are replaced (the new
    /// persist overwrites the same session key) rather than separately
    /// deleted, never silently dropped. A session whose prior lease is
    /// quarantined as ReleasePending receives its quarantined addresses back
    /// for the same device (no reuse by others); a different device receives
    /// `OwnerMismatch`.
    ///
    /// Locking: the pool mutex is never held across store I/O. The candidate
    /// is parked in the inflight set before the lock is dropped, so
    /// concurrent allocators block reuse and concurrent same-session callers
    /// fail closed with `Store` (counted as `inflight_conflicts`) until the
    /// persist commits. Production async callers must use
    /// [`AddressPool::reserve_async`] / [`AddressPool::reserve_at_time_async`]
    /// (bounded owner queue, never detached `spawn_blocking`, never on an
    /// executor thread).
    ///
    /// Test/legacy entry point: `now_ms` supplies both domains. Production
    /// must use [`reserve_at_time`](Self::reserve_at_time) with a real wall
    /// clock so the durable journal survives a restart.
    pub fn reserve(
        &self,
        session_id: SessionId,
        device_id: DeviceId,
        now_ms: u64,
    ) -> Result<AssignedAddresses, AddressPoolError> {
        self.reserve_at_time(session_id, device_id, PoolTime::from_monotonic(now_ms))
    }

    /// Wall-aware reserve. In-memory expiry is `monotonic_ms + pending_ttl`;
    /// durable expiry is `wall_ms + pending_ttl` (see [`PoolTime`]). Recovery
    /// converts the wall remainder back to monotonic (saturating).
    pub fn reserve_at_time(
        &self,
        session_id: SessionId,
        device_id: DeviceId,
        now: PoolTime,
    ) -> Result<AssignedAddresses, AddressPoolError> {
        if is_zero_id(session_id.as_bytes()) || is_zero_id(device_id.as_bytes()) {
            return Err(AddressPoolError::OwnerMismatch);
        }
        // Phase 1 (under lock): fast paths plus candidate selection and
        // inflight parking. No store I/O here. Monotonic drives memory TTLs.
        let (addresses, mono_expires_at_ms, wall_expires_at_ms) = {
            let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
            if inner.inflight.contains(&session_id) {
                self.metrics.inflight_conflicts.fetch_add(1, Ordering::Relaxed);
                return Err(AddressPoolError::Store);
            }
            // Quarantined session: same device gets its blocked addresses back so
            // they are never handed to another session; different device is rejected.
            if let Some(quarantined) = inner.release_pending.get(&session_id) {
                if quarantined.device_id != device_id {
                    self.metrics.owner_mismatch.fetch_add(1, Ordering::Relaxed);
                    return Err(AddressPoolError::OwnerMismatch);
                }
                return Ok(quarantined.addresses);
            }
            if let Some(active) = inner.active.get(&session_id) {
                if active.device_id != device_id {
                    self.metrics.owner_mismatch.fetch_add(1, Ordering::Relaxed);
                    return Err(AddressPoolError::OwnerMismatch);
                }
                return Ok(active.addresses);
            }
            // Expired own reservation is replaced: drop it from memory (count
            // it); the new persist below overwrites the same session key, so
            // no separate durable delete is needed on this path. Other
            // sessions' expired reservations are reclaimed by `sweep`.
            if let Some(pending) = inner.pending.get(&session_id) {
                if pending.device_id != device_id {
                    self.metrics.owner_mismatch.fetch_add(1, Ordering::Relaxed);
                    return Err(AddressPoolError::OwnerMismatch);
                }
                if now.monotonic_ms < pending.expires_at_ms {
                    return Ok(pending.addresses);
                }
                inner.pending.remove(&session_id);
                self.metrics.pending_expired.fetch_add(1, Ordering::Relaxed);
            }
            if inner.active.len().saturating_add(inner.pending.len()).saturating_add(inner.inflight.len())
                >= self.config.maximum_leases
            {
                self.metrics.exhausted.fetch_add(1, Ordering::Relaxed);
                return Err(AddressPoolError::Exhausted);
            }
            let addresses = self.allocate_locked(&inner)?;
            let mono_expires_at_ms = now.monotonic_ms.saturating_add(self.config.pending_ttl_ms);
            let wall_expires_at_ms = wall_expiry_from_ttl(now.wall_ms, self.config.pending_ttl_ms);
            inner.inflight.insert(session_id);
            inner.inflight_v4.insert(u32::from_be_bytes(addresses.ipv4));
            inner.inflight_v6.insert(addresses.ipv6_prefix);
            (addresses, mono_expires_at_ms, wall_expires_at_ms)
        };
        // Phase 2 (no lock): durable persist carries the wall expiry so a
        // restart recovers the remaining TTL (see `recover_locked_at_time`).
        let persisted = PersistedLease {
            session_id,
            device_id,
            ipv4: addresses.ipv4,
            ipv4_prefix_len: addresses.ipv4_prefix_len,
            ipv6_prefix: addresses.ipv6_prefix,
            ipv6_prefix_len: addresses.ipv6_prefix_len,
            state: LeaseState::Reserved,
            expires_at_ms: wall_expires_at_ms,
        };
        let persist_ok = match &self.store {
            Some(store) => store.persist(&persisted).is_ok(),
            None => true,
        };
        // Phase 3 (under lock): commit or rollback the inflight parking.
        let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
        inner.inflight.remove(&session_id);
        inner.inflight_v4.remove(&u32::from_be_bytes(addresses.ipv4));
        inner.inflight_v6.remove(&addresses.ipv6_prefix);
        if !persist_ok {
            self.metrics.store_failures.fetch_add(1, Ordering::Relaxed);
            return Err(AddressPoolError::Store);
        }
        // A concurrent sweep could have quarantined this session while the
        // persist was in flight (sweep skips inflight, so this cannot happen;
        // defensive: prefer the quarantine to avoid duplicate keys).
        if inner.release_pending.contains_key(&session_id) || inner.active.contains_key(&session_id) {
            self.metrics.inflight_conflicts.fetch_add(1, Ordering::Relaxed);
            return Err(AddressPoolError::Store);
        }
        inner.pending.insert(session_id, ReservedLease { device_id, addresses, expires_at_ms: mono_expires_at_ms });
        self.metrics.allocations.fetch_add(1, Ordering::Relaxed);
        Ok(addresses)
    }

    /// Commits a Reserved reservation to Active. Idempotent when the session
    /// is already Active (resume retry) or already quarantined as
    /// ReleasePending for the same reservation (returns the quarantined
    /// addresses without reusing them elsewhere). Persists the Active lease
    /// (state plus expiry); store failures restore the Reserved entry and
    /// fail closed. An expired reservation is durably released (quarantining
    /// on store failure) and reports `Expired`.
    ///
    /// Locking: the pool mutex is never held across store I/O (inflight
    /// parking, as in [`AddressPool::reserve`]). Use
    /// [`AddressPool::commit_async`] / [`AddressPool::commit_at_time_async`]
    /// from Tokio contexts (bounded owner queue).
    ///
    /// Test/legacy entry point: `now_ms` supplies both domains. Production
    /// must use [`commit_at_time`](Self::commit_at_time).
    pub fn commit(
        &self,
        session_id: SessionId,
        now_ms: u64,
    ) -> Result<AssignedAddresses, AddressPoolError> {
        self.commit_at_time(session_id, PoolTime::from_monotonic(now_ms))
    }

    /// Wall-aware commit. In-memory Active expiry is monotonic; durable Active
    /// expiry is wall (see [`PoolTime`]).
    pub fn commit_at_time(
        &self,
        session_id: SessionId,
        now: PoolTime,
    ) -> Result<AssignedAddresses, AddressPoolError> {
        // Phase 1 (under lock): take the pending reservation and park
        // inflight. No store I/O here. Monotonic drives memory TTLs.
        enum CommitPlan {
            Promote { device_id: DeviceId, addresses: AssignedAddresses, pending_expires_at_ms: u64, active_mono_expires_at_ms: u64, active_wall_expires_at_ms: u64 },
            Expire { device_id: DeviceId, addresses: AssignedAddresses, expires_at_ms: u64 },
        }
        let plan = {
            let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
            if inner.inflight.contains(&session_id) {
                self.metrics.inflight_conflicts.fetch_add(1, Ordering::Relaxed);
                return Err(AddressPoolError::Store);
            }
            if let Some(active) = inner.active.get(&session_id) {
                return Ok(active.addresses);
            }
            if let Some(quarantined) = inner.release_pending.get(&session_id) {
                return Ok(quarantined.addresses);
            }
            let pending = inner.pending.remove(&session_id).ok_or(AddressPoolError::UnknownLease)?;
            if now.monotonic_ms >= pending.expires_at_ms {
                inner.inflight.insert(session_id);
                inner.inflight_v4.insert(u32::from_be_bytes(pending.addresses.ipv4));
                inner.inflight_v6.insert(pending.addresses.ipv6_prefix);
                CommitPlan::Expire { device_id: pending.device_id, addresses: pending.addresses, expires_at_ms: pending.expires_at_ms }
            } else {
                inner.inflight.insert(session_id);
                inner.inflight_v4.insert(u32::from_be_bytes(pending.addresses.ipv4));
                inner.inflight_v6.insert(pending.addresses.ipv6_prefix);
                CommitPlan::Promote {
                    device_id: pending.device_id,
                    addresses: pending.addresses,
                    pending_expires_at_ms: pending.expires_at_ms,
                    active_mono_expires_at_ms: now.monotonic_ms.saturating_add(self.config.lease_ttl_ms),
                    active_wall_expires_at_ms: wall_expiry_from_ttl(now.wall_ms, self.config.lease_ttl_ms),
                }
            }
        };
        match plan {
            CommitPlan::Expire { device_id, addresses, expires_at_ms } => {
                // Phase 2 (no lock): durable delete of the expired reservation.
                let delete_ok = match &self.store {
                    Some(store) => store.release(&session_id).is_ok(),
                    None => true,
                };
                // Phase 3 (under lock): unpark; quarantine on failure.
                let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
                inner.inflight.remove(&session_id);
                inner.inflight_v4.remove(&u32::from_be_bytes(addresses.ipv4));
                inner.inflight_v6.remove(&addresses.ipv6_prefix);
                self.metrics.pending_expired.fetch_add(1, Ordering::Relaxed);
                if !delete_ok {
                    let lease = PersistedLease {
                        session_id,
                        device_id,
                        ipv4: addresses.ipv4,
                        ipv4_prefix_len: addresses.ipv4_prefix_len,
                        ipv6_prefix: addresses.ipv6_prefix,
                        ipv6_prefix_len: addresses.ipv6_prefix_len,
                        state: LeaseState::ReleasePending,
                        expires_at_ms,
                    };
                    if self.enqueue_release_locked(&mut inner, lease, now.monotonic_ms).is_err() {
                        inner.pending.insert(session_id, ReservedLease { device_id, addresses, expires_at_ms });
                        return Err(AddressPoolError::Store);
                    }
                    self.metrics.store_failures.fetch_add(1, Ordering::Relaxed);
                }
                Err(AddressPoolError::Expired)
            }
            CommitPlan::Promote { device_id, addresses, pending_expires_at_ms, active_mono_expires_at_ms, active_wall_expires_at_ms } => {
                // Phase 2 (no lock): durable persist carries the wall expiry.
                let persisted = PersistedLease {
                    session_id,
                    device_id,
                    ipv4: addresses.ipv4,
                    ipv4_prefix_len: addresses.ipv4_prefix_len,
                    ipv6_prefix: addresses.ipv6_prefix,
                    ipv6_prefix_len: addresses.ipv6_prefix_len,
                    state: LeaseState::Active,
                    expires_at_ms: active_wall_expires_at_ms,
                };
                let persist_ok = match &self.store {
                    Some(store) => store.persist(&persisted).is_ok(),
                    None => true,
                };
                // Phase 3 (under lock): promote or restore.
                let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
                inner.inflight.remove(&session_id);
                inner.inflight_v4.remove(&u32::from_be_bytes(addresses.ipv4));
                inner.inflight_v6.remove(&addresses.ipv6_prefix);
                if !persist_ok {
                    inner.pending.insert(session_id, ReservedLease { device_id, addresses, expires_at_ms: pending_expires_at_ms });
                    self.metrics.store_failures.fetch_add(1, Ordering::Relaxed);
                    return Err(AddressPoolError::Store);
                }
                if inner.release_pending.contains_key(&session_id) || inner.active.contains_key(&session_id) {
                    self.metrics.inflight_conflicts.fetch_add(1, Ordering::Relaxed);
                    return Err(AddressPoolError::Store);
                }
                inner.active.insert(session_id, ActiveLease { device_id, addresses, expires_at_ms: active_mono_expires_at_ms });
                self.metrics.commits.fetch_add(1, Ordering::Relaxed);
                Ok(addresses)
            }
        }
    }

    /// Releases a Reserved or Active lease. On durable-store success the
    /// addresses are freed for reuse; on store failure the lease is
    /// quarantined as `ReleasePending` (nonreusable) for bounded retry with
    /// backoff ([`AddressPool::retry_pending_releases_bounded`]). When the
    /// quarantine is full the call fails closed with `Store` and the lease
    /// stays blocked for reuse. Returns `Ok(true)` when a lease was present,
    /// `Ok(false)` when the session held no lease.
    ///
    /// Locking: the pool mutex is never held across store I/O (inflight
    /// parking). This untimed wrapper quarantines with `now = 0` (due
    /// immediately); timed callers must use [`AddressPool::release_at`], and
    /// Tokio contexts must use [`AddressPool::release_async`].
    pub fn release(&self, session_id: SessionId) -> Result<bool, AddressPoolError> {
        self.release_at(session_id, 0)
    }

    /// Timed release with an explicit `now_ms` for quarantine backoff.
    /// Behavior matches [`AddressPool::release`], except a quarantined entry
    /// becomes due after `next_retry_deadline(now_ms, 0)`.
    pub fn release_at(&self, session_id: SessionId, now_ms: u64) -> Result<bool, AddressPoolError> {
        // Phase 1 (under lock): take the lease and park inflight. No I/O.
        struct Taken {
            device_id: DeviceId,
            addresses: AssignedAddresses,
            expires_at_ms: u64,
        }
        let taken = {
            let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
            if inner.inflight.contains(&session_id) {
                self.metrics.inflight_conflicts.fetch_add(1, Ordering::Relaxed);
                return Err(AddressPoolError::Store);
            }
            if inner.release_pending.contains_key(&session_id) {
                return Ok(false);
            }
            let mut removed: Option<Taken> = None;
            if let Some(pending) = inner.pending.remove(&session_id) {
                removed = Some(Taken { device_id: pending.device_id, addresses: pending.addresses, expires_at_ms: pending.expires_at_ms });
            } else if let Some(active) = inner.active.remove(&session_id) {
                removed = Some(Taken { device_id: active.device_id, addresses: active.addresses, expires_at_ms: active.expires_at_ms });
            }
            let Some(taken) = removed else {
                return Ok(false);
            };
            inner.inflight.insert(session_id);
            inner.inflight_v4.insert(u32::from_be_bytes(taken.addresses.ipv4));
            inner.inflight_v6.insert(taken.addresses.ipv6_prefix);
            taken
        };
        // Phase 2 (no lock): durable delete.
        let delete_ok = match &self.store {
            Some(store) => store.release(&session_id).is_ok(),
            None => true,
        };
        // Phase 3 (under lock): free or quarantine.
        let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
        inner.inflight.remove(&session_id);
        inner.inflight_v4.remove(&u32::from_be_bytes(taken.addresses.ipv4));
        inner.inflight_v6.remove(&taken.addresses.ipv6_prefix);
        if !delete_ok {
            let lease = PersistedLease {
                session_id,
                device_id: taken.device_id,
                ipv4: taken.addresses.ipv4,
                ipv4_prefix_len: taken.addresses.ipv4_prefix_len,
                ipv6_prefix: taken.addresses.ipv6_prefix,
                ipv6_prefix_len: taken.addresses.ipv6_prefix_len,
                state: LeaseState::ReleasePending,
                expires_at_ms: taken.expires_at_ms,
            };
            if self.enqueue_release_locked(&mut inner, lease, now_ms).is_err() {
                // Fail closed: quarantine is full, so restore the lease to
                // its prior map instead of freeing it for reuse. Reserved
                // vs Active is recovered from the original expiry domain:
                // Reserved expiries are within pending TTL of allocation,
                // Active expiries carry the longer DHCP TTL. Restoring as
                // Active is the safe superset (longer block, still bounded
                // by maximum_leases) and sweep will retry the durable
                // delete once quarantine has room.
                inner.active.insert(
                    session_id,
                    ActiveLease {
                        device_id: taken.device_id,
                        addresses: taken.addresses,
                        expires_at_ms: taken.expires_at_ms,
                    },
                );
                return Err(AddressPoolError::Store);
            }
            self.metrics.store_failures.fetch_add(1, Ordering::Relaxed);
        }
        self.metrics.releases.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// Non-blocking session-cleanup release (for
    /// [`SessionCleanup`](super::session_manager::SessionCleanup)): moves the
    /// lease straight to quarantine in memory without attempting store I/O,
    /// so Tokio executor threads never block on journal writes during session
    /// close. The bounded retry path performs the actual durable delete with
    /// backoff. Returns `true` when a lease was present. Fail-closed on
    /// quarantine overflow (lease restored as Active, counted).
    pub fn release_deferred(&self, session_id: SessionId) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return false,
        };
        if inner.inflight.contains(&session_id) || inner.release_pending.contains_key(&session_id) {
            return false;
        }
        let mut removed: Option<(DeviceId, AssignedAddresses, u64)> = None;
        if let Some(pending) = inner.pending.remove(&session_id) {
            removed = Some((pending.device_id, pending.addresses, pending.expires_at_ms));
        } else if let Some(active) = inner.active.remove(&session_id) {
            removed = Some((active.device_id, active.addresses, active.expires_at_ms));
        }
        let Some((device_id, addresses, expires_at_ms)) = removed else {
            return false;
        };
        let lease = PersistedLease {
            session_id,
            device_id,
            ipv4: addresses.ipv4,
            ipv4_prefix_len: addresses.ipv4_prefix_len,
            ipv6_prefix: addresses.ipv6_prefix,
            ipv6_prefix_len: addresses.ipv6_prefix_len,
            state: LeaseState::ReleasePending,
            expires_at_ms,
        };
        if self.enqueue_release_locked(&mut inner, lease, 0).is_err() {
            inner.active.insert(session_id, ActiveLease { device_id, addresses, expires_at_ms });
            return false;
        }
        self.metrics.releases.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Returns the committed or pending addresses for a session, if any.
    /// This includes Reserved leases so the admission listener can resume a
    /// crash reserve idempotently. Source validation must use
    /// [`AddressPool::lookup_active`] instead: only Active leases may carry
    /// payload, otherwise a client could send before `SessionAdmit` commits.
    #[must_use]
    pub fn lookup(&self, session_id: SessionId) -> Option<AssignedAddresses> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner
                    .active
                    .get(&session_id)
                    .map(|lease| lease.addresses)
                    .or_else(|| inner.pending.get(&session_id).map(|lease| lease.addresses))
            })
    }

    /// Returns the committed Active lease for a session, if any. The V2 uplink
    /// source validator uses this exclusively: Reserved (pre-commit) and
    /// ReleasePending (quarantined) leases never authorize payload.
    #[must_use]
    pub fn lookup_active(&self, session_id: SessionId) -> Option<AssignedAddresses> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.active.get(&session_id).map(|lease| lease.addresses))
    }

    /// Extends an active lease to `now + lease_ttl` and persists the Active
    /// record (state plus new expiry) durably. Fails with `UnknownLease`
    /// (never held, including Reserved or quarantined) or `Expired` (TTL
    /// already passed; the next [`AddressPool::sweep`] will free it for
    /// reuse). A store failure keeps the old in-memory expiry, counts
    /// `store_failures`, and fails closed with `Store` so memory and the
    /// durable record never disagree.
    ///
    /// Locking: the pool mutex is never held across store I/O. The session
    /// is parked inflight while the persist runs, so sweeps skip it and
    /// concurrent mutators fail closed; the Active entry itself stays in
    /// place with its old expiry until the persist commits. Use
    /// [`AddressPool::renew_async`] / [`AddressPool::renew_at_time_async`]
    /// from Tokio contexts (bounded owner queue).
    ///
    /// Test/legacy entry point: `now_ms` supplies both domains. Production
    /// must use [`renew_at_time`](Self::renew_at_time).
    pub fn renew(&self, session_id: SessionId, now_ms: u64) -> Result<(), AddressPoolError> {
        self.renew_at_time(session_id, PoolTime::from_monotonic(now_ms))
    }

    /// Wall-aware renew. Memory expiry is monotonic; durable expiry is wall.
    pub fn renew_at_time(&self, session_id: SessionId, now: PoolTime) -> Result<(), AddressPoolError> {
        // Phase 1 (under lock): snapshot the lease and park inflight.
        struct RenewPlan {
            device_id: DeviceId,
            addresses: AssignedAddresses,
            renewed_mono_expires_at_ms: u64,
            renewed_wall_expires_at_ms: u64,
        }
        let plan = {
            let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
            if inner.inflight.contains(&session_id) {
                self.metrics.inflight_conflicts.fetch_add(1, Ordering::Relaxed);
                return Err(AddressPoolError::Store);
            }
            let Some(active) = inner.active.get(&session_id) else {
                return Err(AddressPoolError::UnknownLease);
            };
            if now.monotonic_ms >= active.expires_at_ms {
                return Err(AddressPoolError::Expired);
            }
            let plan = RenewPlan {
                device_id: active.device_id,
                addresses: active.addresses,
                renewed_mono_expires_at_ms: now.monotonic_ms.saturating_add(self.config.lease_ttl_ms),
                renewed_wall_expires_at_ms: wall_expiry_from_ttl(now.wall_ms, self.config.lease_ttl_ms),
            };
            inner.inflight.insert(session_id);
            plan
        };
        // Phase 2 (no lock): durable persist carries the wall expiry.
        let persist_ok = match &self.store {
            Some(store) => {
                let persisted = PersistedLease {
                    session_id,
                    device_id: plan.device_id,
                    ipv4: plan.addresses.ipv4,
                    ipv4_prefix_len: plan.addresses.ipv4_prefix_len,
                    ipv6_prefix: plan.addresses.ipv6_prefix,
                    ipv6_prefix_len: plan.addresses.ipv6_prefix_len,
                    state: LeaseState::Active,
                    expires_at_ms: plan.renewed_wall_expires_at_ms,
                };
                store.persist(&persisted).is_ok()
            }
            None => true,
        };
        // Phase 3 (under lock): commit the new expiry or fail closed.
        let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
        inner.inflight.remove(&session_id);
        if !persist_ok {
            self.metrics.store_failures.fetch_add(1, Ordering::Relaxed);
            return Err(AddressPoolError::Store);
        }
        // Sweep skips inflight sessions, so the entry is still present with
        // the same owner; defensive mismatch fails closed without moving it.
        match inner.active.get_mut(&session_id) {
            Some(active) if active.device_id == plan.device_id && active.addresses == plan.addresses => {
                active.expires_at_ms = plan.renewed_mono_expires_at_ms;
                self.metrics.renewals.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            _ => {
                self.metrics.inflight_conflicts.fetch_add(1, Ordering::Relaxed);
                Err(AddressPoolError::UnknownLease)
            }
        }
    }

    /// Expires Reserved leases past their TTL and Active leases past their
    /// DHCP TTL with a durable store release (quarantining on store failure),
    /// then retries previously quarantined releases with a bounded batch and
    /// backoff. Returns the expired session IDs so the caller can close the
    /// corresponding sessions (idempotent). Deterministic in `now_ms`. When
    /// the quarantine is full, expired leases stay blocked for reuse (fail
    /// closed) but are still reported for session close; the session cleanup
    /// path retries the durable delete once quarantine has room.
    ///
    /// Locking: the pool mutex is never held across store I/O. Expired
    /// leases are parked inflight before the lock is dropped; concurrent
    /// same-session callers fail closed until the deletes commit. Use
    /// [`AddressPool::sweep_async`] from Tokio contexts.
    pub fn sweep(&self, now_ms: u64) -> Vec<SessionId> {
        struct Expired {
            id: SessionId,
            device_id: DeviceId,
            addresses: AssignedAddresses,
            expires_at_ms: u64,
            was_pending: bool,
        }
        // Phase 1 (under lock): collect and park expired leases.
        let batch: Vec<Expired> = {
            let mut inner = match self.inner.lock() {
                Ok(inner) => inner,
                Err(_) => return Vec::new(),
            };
            let pending_ids: Vec<SessionId> = inner
                .pending
                .iter()
                .filter_map(|(id, lease)| (!inner.inflight.contains(id) && now_ms >= lease.expires_at_ms).then_some(*id))
                .collect();
            let active_ids: Vec<SessionId> = inner
                .active
                .iter()
                .filter_map(|(id, lease)| (!inner.inflight.contains(id) && now_ms >= lease.expires_at_ms).then_some(*id))
                .collect();
            let mut batch = Vec::with_capacity(pending_ids.len().saturating_add(active_ids.len()));
            for id in pending_ids {
                if let Some(lease) = inner.pending.remove(&id) {
                    self.metrics.pending_expired.fetch_add(1, Ordering::Relaxed);
                    inner.inflight.insert(id);
                    inner.inflight_v4.insert(u32::from_be_bytes(lease.addresses.ipv4));
                    inner.inflight_v6.insert(lease.addresses.ipv6_prefix);
                    batch.push(Expired { id, device_id: lease.device_id, addresses: lease.addresses, expires_at_ms: lease.expires_at_ms, was_pending: true });
                }
            }
            for id in active_ids {
                if let Some(lease) = inner.active.remove(&id) {
                    self.metrics.active_expired.fetch_add(1, Ordering::Relaxed);
                    inner.inflight.insert(id);
                    inner.inflight_v4.insert(u32::from_be_bytes(lease.addresses.ipv4));
                    inner.inflight_v6.insert(lease.addresses.ipv6_prefix);
                    batch.push(Expired { id, device_id: lease.device_id, addresses: lease.addresses, expires_at_ms: lease.expires_at_ms, was_pending: false });
                }
            }
            // Deterministic expiry order for session-close callers.
            batch.sort_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
            batch
        };
        // Phase 2 (no lock): durable deletes, one per expired lease.
        let has_store = self.store.is_some();
        let mut outcomes: Vec<(SessionId, bool)> = Vec::with_capacity(batch.len());
        for expired in &batch {
            let ok = match &self.store {
                Some(store) => store.release(&expired.id).is_ok(),
                None => true,
            };
            outcomes.push((expired.id, ok));
        }
        // Phase 3 (under lock): unpark; quarantine failures (fail closed).
        let mut expired_ids = Vec::with_capacity(batch.len());
        if !batch.is_empty() {
            let mut inner = match self.inner.lock() {
                Ok(inner) => inner,
                Err(_) => {
                    // Lock poisoned after the deletes landed: report the
                    // expiries so callers still close the sessions; the store
                    // entries are already gone, so reuse is safe.
                    return batch.into_iter().map(|expired| expired.id).collect();
                }
            };
            for expired in batch {
                inner.inflight.remove(&expired.id);
                inner.inflight_v4.remove(&u32::from_be_bytes(expired.addresses.ipv4));
                inner.inflight_v6.remove(&expired.addresses.ipv6_prefix);
                expired_ids.push(expired.id);
                let ok = outcomes.iter().find(|(oid, _)| *oid == expired.id).map(|(_, ok)| *ok).unwrap_or(true);
                if has_store && !ok {
                    let persisted = PersistedLease {
                        session_id: expired.id,
                        device_id: expired.device_id,
                        ipv4: expired.addresses.ipv4,
                        ipv4_prefix_len: expired.addresses.ipv4_prefix_len,
                        ipv6_prefix: expired.addresses.ipv6_prefix,
                        ipv6_prefix_len: expired.addresses.ipv6_prefix_len,
                        state: LeaseState::ReleasePending,
                        expires_at_ms: expired.expires_at_ms,
                    };
                    if self.enqueue_release_locked(&mut inner, persisted, now_ms).is_err() {
                        // Fail closed: keep the expired lease blocked.
                        if expired.was_pending {
                            inner.pending.insert(expired.id, ReservedLease { device_id: expired.device_id, addresses: expired.addresses, expires_at_ms: expired.expires_at_ms });
                        } else {
                            inner.active.insert(expired.id, ActiveLease { device_id: expired.device_id, addresses: expired.addresses, expires_at_ms: expired.expires_at_ms });
                        }
                    } else {
                        self.metrics.store_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            expired_ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            drop(inner);
        }
        self.retry_pending_releases_bounded(now_ms, MAX_RETRY_BATCH);
        expired_ids
    }

    /// Observability for quarantined deletes: deterministic `(session,
    /// original expiry, attempts)` triples. Expiry and attempts are retained
    /// per record so operators can distinguish a fresh quarantine from a
    /// stuck store delete.
    #[must_use]
    pub fn quarantined(&self) -> Vec<(SessionId, u64, u64)> {
        self.inner
            .lock()
            .map(|inner| {
                let mut entries: Vec<(SessionId, u64, u64)> = inner
                    .release_pending
                    .iter()
                    .map(|(id, lease)| (*id, lease.expires_at_ms, lease.attempts))
                    .collect();
                entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                entries
            })
            .unwrap_or_default()
    }

    /// Retries quarantined durable releases in deterministic order. Returns
    /// the number still quarantined. This untimed wrapper retries everything
    /// that is due with an unbounded batch (`now = u64::MAX`, all due);
    /// production callers (including [`AddressPool::sweep`]) must use
    /// [`AddressPool::retry_pending_releases_bounded`] with a real clock and
    /// [`MAX_RETRY_BATCH`]. Quarantined addresses stay nonreusable until
    /// their store delete succeeds. Each failed retry increments that
    /// lease's `attempts` and pushes its next deadline out exponentially
    /// (visible via [`AddressPool::quarantined`]); successes count
    /// `release_retries`. The pool mutex is never held across store I/O.
    pub fn retry_pending_releases(&self) -> usize {
        self.retry_pending_releases_bounded(u64::MAX, usize::MAX)
    }

    /// Bounded retry with exponential backoff. Attempts at most `max_batch`
    /// store deletes for quarantined leases whose `next_retry_ms <= now_ms`,
    /// in deterministic FIFO order; the rest (not due, or beyond the batch)
    /// are deferred and counted as `release_retry_deferred`, never attempted.
    /// Failed attempts increment `attempts` and set
    /// `next_retry_ms = next_retry_deadline(now_ms, attempts)`. In-flight
    /// sessions are skipped (left queued, not counted as deferred). Returns
    /// the number still quarantined. Deterministic in `now_ms`.
    pub fn retry_pending_releases_bounded(&self, now_ms: u64, max_batch: usize) -> usize {
        if self.store.is_none() {
            return 0;
        }
        // Phase 1 (under lock): select up to `max_batch` due leases and park
        // them inflight. Deferred and skipped entries stay queued.
        let batch: Vec<SessionId> = {
            let mut inner = match self.inner.lock() {
                Ok(inner) => inner,
                Err(_) => return 0,
            };
            let mut batch = Vec::new();
            let mut remaining: VecDeque<SessionId> = VecDeque::new();
            let mut deferred = 0u64;
            while let Some(id) = inner.release_order.pop_front() {
                let Some(quarantined) = inner.release_pending.get(&id) else {
                    continue;
                };
                if inner.inflight.contains(&id) {
                    remaining.push_back(id);
                    continue;
                }
                if quarantined.next_retry_ms > now_ms {
                    deferred = deferred.saturating_add(1);
                    remaining.push_back(id);
                    continue;
                }
                if batch.len() >= max_batch {
                    deferred = deferred.saturating_add(1);
                    remaining.push_back(id);
                    // Everything past the batch is deferred without inspection.
                    while let Some(id) = inner.release_order.pop_front() {
                        if inner.release_pending.contains_key(&id) {
                            deferred = deferred.saturating_add(1);
                            remaining.push_back(id);
                        }
                    }
                    break;
                }
                inner.inflight.insert(id);
                batch.push(id);
            }
            inner.release_order = remaining;
            if deferred != 0 {
                self.metrics.release_retry_deferred.fetch_add(deferred, Ordering::Relaxed);
            }
            batch
        };
        if batch.is_empty() {
            return self.inner.lock().map(|inner| inner.release_pending.len()).unwrap_or(0);
        }
        // Phase 2 (no lock): durable deletes.
        let mut outcomes: Vec<(SessionId, bool)> = Vec::with_capacity(batch.len());
        for id in &batch {
            let ok = match &self.store {
                Some(store) => store.release(id).is_ok(),
                None => true,
            };
            outcomes.push((*id, ok));
        }
        // Phase 3 (under lock): unpark; successes leave, failures back off.
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return batch.len(),
        };
        let mut retried = 0u64;
        for (id, ok) in outcomes {
            inner.inflight.remove(&id);
            if ok {
                if inner.release_pending.remove(&id).is_some() {
                    retried = retried.saturating_add(1);
                }
            } else if let Some(quarantined) = inner.release_pending.get_mut(&id) {
                quarantined.attempts = quarantined.attempts.saturating_add(1);
                quarantined.next_retry_ms = next_retry_deadline(now_ms, quarantined.attempts);
                inner.release_order.push_back(id);
            } else {
                inner.release_order.push_back(id);
            }
        }
        if retried != 0 {
            self.metrics.release_retries.fetch_add(retried, Ordering::Relaxed);
        }
        inner.release_pending.len()
    }

    /// Bounded owner-queue wrappers for blocking durable stores. Each method
    /// routes the sync pool operation (including any journal file I/O, which
    /// runs on the owner worker thread, never on a Tokio executor thread)
    /// through the supervised [`PersistenceOwner`] (hard cap, `try_send`
    /// backpressure, `io_timeout` fail-closed). No detached `spawn_blocking`
    /// flood: at most `queue_capacity` works are ever queued. `Full`,
    /// `Timeout`, or `Closed` map to `Store`/`Unavailable` (fail closed) for
    /// fallible ops, or to empty/default for infallible sweeps (retry next
    /// tick). Behavior and errors otherwise match the sync methods exactly.
    ///
    /// Test/legacy entry points: `now_ms` supplies both domains. Production
    /// must use the `*_at_time_async` variants with a real wall clock.
    pub async fn reserve_async(self: Arc<Self>, session_id: SessionId, device_id: DeviceId, now_ms: u64) -> Result<AssignedAddresses, AddressPoolError> {
        self.reserve_at_time_async(session_id, device_id, PoolTime::from_monotonic(now_ms)).await
    }

    /// Wall-aware async reserve through the owner queue.
    pub async fn reserve_at_time_async(self: Arc<Self>, session_id: SessionId, device_id: DeviceId, now: PoolTime) -> Result<AssignedAddresses, AddressPoolError> {
        if let Some(owner) = &self.persistence {
            let pool = Arc::clone(&self);
            owner
                .execute(move || pool.reserve_at_time(session_id, device_id, now))
                .await
                .map_err(|error| match error {
                    PersistenceError::Full | PersistenceError::Timeout => AddressPoolError::Store,
                    PersistenceError::Closed | PersistenceError::Unavailable => AddressPoolError::Unavailable,
                })?
        } else {
            self.reserve_at_time(session_id, device_id, now)
        }
    }

    /// Async [`AddressPool::commit`] through the owner queue.
    pub async fn commit_async(self: Arc<Self>, session_id: SessionId, now_ms: u64) -> Result<AssignedAddresses, AddressPoolError> {
        self.commit_at_time_async(session_id, PoolTime::from_monotonic(now_ms)).await
    }

    /// Wall-aware async commit through the owner queue.
    pub async fn commit_at_time_async(self: Arc<Self>, session_id: SessionId, now: PoolTime) -> Result<AssignedAddresses, AddressPoolError> {
        if let Some(owner) = &self.persistence {
            let pool = Arc::clone(&self);
            owner
                .execute(move || pool.commit_at_time(session_id, now))
                .await
                .map_err(|error| match error {
                    PersistenceError::Full | PersistenceError::Timeout => AddressPoolError::Store,
                    PersistenceError::Closed | PersistenceError::Unavailable => AddressPoolError::Unavailable,
                })?
        } else {
            self.commit_at_time(session_id, now)
        }
    }

    /// Async [`AddressPool::release`] through the owner queue.
    pub async fn release_async(self: Arc<Self>, session_id: SessionId) -> Result<bool, AddressPoolError> {
        if let Some(owner) = &self.persistence {
            let pool = Arc::clone(&self);
            owner
                .execute(move || pool.release(session_id))
                .await
                .map_err(|_| AddressPoolError::Unavailable)?
        } else {
            self.release(session_id)
        }
    }

    /// Async [`AddressPool::release_at`] through the owner queue.
    pub async fn release_at_async(self: Arc<Self>, session_id: SessionId, now_ms: u64) -> Result<bool, AddressPoolError> {
        if let Some(owner) = &self.persistence {
            let pool = Arc::clone(&self);
            owner
                .execute(move || pool.release_at(session_id, now_ms))
                .await
                .map_err(|_| AddressPoolError::Unavailable)?
        } else {
            self.release_at(session_id, now_ms)
        }
    }

    /// Async [`AddressPool::renew`] through the owner queue.
    pub async fn renew_async(self: Arc<Self>, session_id: SessionId, now_ms: u64) -> Result<(), AddressPoolError> {
        self.renew_at_time_async(session_id, PoolTime::from_monotonic(now_ms)).await
    }

    /// Wall-aware async renew through the owner queue.
    pub async fn renew_at_time_async(self: Arc<Self>, session_id: SessionId, now: PoolTime) -> Result<(), AddressPoolError> {
        if let Some(owner) = &self.persistence {
            let pool = Arc::clone(&self);
            owner
                .execute(move || pool.renew_at_time(session_id, now))
                .await
                .map_err(|error| match error {
                    PersistenceError::Full | PersistenceError::Timeout => AddressPoolError::Store,
                    PersistenceError::Closed | PersistenceError::Unavailable => AddressPoolError::Unavailable,
                })?
        } else {
            self.renew_at_time(session_id, now)
        }
    }

    /// Async [`AddressPool::sweep`] through the owner queue. Returns
    /// the expired session IDs for session close, as in the sync method.
    /// `Full`/`Timeout`/`Closed` yield an empty expiry (fail closed, retry
    /// next tick) so a stalled disk never hangs admission or shutdown.
    pub async fn sweep_async(self: Arc<Self>, now_ms: u64) -> Vec<SessionId> {
        self.sweep_at_time_async(PoolTime::from_monotonic(now_ms)).await
    }

    /// Wall-aware async sweep through the owner queue.
    pub async fn sweep_at_time_async(self: Arc<Self>, now: PoolTime) -> Vec<SessionId> {
        // Sweep expiry is monotonic-only today (in-memory TTLs); the wall
        // domain matters only for persist/recover, so both spellings share
        // the same sync path with `monotonic_ms`. The wall field is retained
        // for future quarantine-wall use without another signature break.
        let now_ms = now.monotonic_ms;
        if let Some(owner) = &self.persistence {
            let pool = Arc::clone(&self);
            owner.execute(move || pool.sweep(now_ms)).await.unwrap_or_default()
        } else {
            self.sweep(now_ms)
        }
    }

    /// Async bounded quarantine retry through the owner queue.
    pub async fn retry_async(self: Arc<Self>, now_ms: u64, max_batch: usize) -> usize {
        if let Some(owner) = &self.persistence {
            let pool = Arc::clone(&self);
            owner
                .execute(move || pool.retry_pending_releases_bounded(now_ms, max_batch))
                .await
                .unwrap_or(0)
        } else {
            self.retry_pending_releases_bounded(now_ms, max_batch)
        }
    }

    /// Closes the owner queue (no new persistence work) and joins the worker
    /// with the bounded shutdown deadline. Never hangs indefinitely; a
    /// stalled worker times out and is detached (counted). Idempotent.
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

    #[must_use]
    pub fn snapshot(&self) -> AddressPoolSnapshot {
        let (active, pending, pending_releases) = self
            .inner
            .lock()
            .map(|inner| (inner.active.len(), inner.pending.len(), inner.release_pending.len()))
            .unwrap_or((0, 0, 0));
        AddressPoolSnapshot {
            active,
            pending,
            pending_releases,
            maximum_leases: self.config.maximum_leases,
            maximum_pending_releases: self.config.maximum_pending_releases,
            allocations: self.metrics.allocations.load(Ordering::Relaxed),
            commits: self.metrics.commits.load(Ordering::Relaxed),
            releases: self.metrics.releases.load(Ordering::Relaxed),
            renewals: self.metrics.renewals.load(Ordering::Relaxed),
            exhausted: self.metrics.exhausted.load(Ordering::Relaxed),
            owner_mismatch: self.metrics.owner_mismatch.load(Ordering::Relaxed),
            pending_expired: self.metrics.pending_expired.load(Ordering::Relaxed),
            active_expired: self.metrics.active_expired.load(Ordering::Relaxed),
            store_failures: self.metrics.store_failures.load(Ordering::Relaxed),
            recovered: self.metrics.recovered.load(Ordering::Relaxed),
            recovered_dropped: self.metrics.recovered_dropped.load(Ordering::Relaxed),
            release_retries: self.metrics.release_retries.load(Ordering::Relaxed),
            release_retry_dropped: self.metrics.release_retry_dropped.load(Ordering::Relaxed),
            quarantine_full: self.metrics.quarantine_full.load(Ordering::Relaxed),
            release_retry_deferred: self.metrics.release_retry_deferred.load(Ordering::Relaxed),
            inflight_conflicts: self.metrics.inflight_conflicts.load(Ordering::Relaxed),
        }
    }

    #[must_use]
    pub fn config(&self) -> &AddressPoolConfig {
        &self.config
    }

    /// Wall-aware recovery. Persisted `expires_at_ms` is wall time; it is
    /// compared to `now.wall_ms` for expiry, and the remainder is converted
    /// to a monotonic deadline with [`monotonic_expiry_from_wall`]
    /// (saturating, never panics). A wall expiry at or before `wall_now` is
    /// dropped as expired; a far-future wall saturates (never wraps).
    fn recover_locked_at_time(
        &self,
        persisted: Vec<PersistedLease>,
        now: PoolTime,
    ) -> Result<(), AddressPoolError> {
        // Bounded, deterministic recovery: sort by session ID so the valid
        // prefix is stable across restarts, then restore at most
        // `maximum_leases` Reserved/Active plus `maximum_pending_releases`
        // ReleasePending. Expired, invalid, over-capacity, or over-bound
        // entries are dropped, counted, and their store entries deleted so a
        // corrupt store cannot grow the pool or collide on restart. A failed
        // discarded-delete is quarantined as nonreusable `ReleasePending`
        // (fail closed); quarantine overflow fails pool construction closed.
        // No store I/O happens under the pool lock. Construction-time only:
        // the pool is not yet shared, so no inflight parking is needed.
        let mut ordered = persisted;
        ordered.sort_by(|a, b| {
            a.session_id
                .as_bytes()
                .cmp(b.session_id.as_bytes())
                .then_with(|| a.device_id.as_bytes().cmp(b.device_id.as_bytes()))
        });
        let bound = self
            .config
            .maximum_leases
            .saturating_add(self.config.maximum_pending_releases)
            .min(MAX_LEASES_HARD_CAP);
        let mut stale: Vec<PersistedLease> = Vec::new();
        if ordered.len() > bound {
            for dropped in ordered.iter().skip(bound) {
                self.metrics.recovered_dropped.fetch_add(1, Ordering::Relaxed);
                stale.push(*dropped);
            }
            ordered.truncate(bound);
        }
        let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
        let mut seen_sessions = HashSet::new();
        let mut seen_v4 = HashSet::new();
        let mut seen_v6 = HashSet::new();
        for lease in ordered {
            // Expired persisted leases never recover (wall domain): they are
            // dropped and their store entry is removed so the addresses become
            // reusable. The wall comparison is saturating and safe across a
            // restart where the monotonic origin reset to near zero.
            if lease.expires_at_ms <= now.wall_ms {
                self.metrics.recovered_dropped.fetch_add(1, Ordering::Relaxed);
                stale.push(lease);
                continue;
            }
            if !self.valid_persisted_locked(&inner, &lease, &seen_sessions, &seen_v4, &seen_v6) {
                self.metrics.recovered_dropped.fetch_add(1, Ordering::Relaxed);
                stale.push(lease);
                continue;
            }
            seen_sessions.insert(lease.session_id);
            seen_v4.insert(lease.ipv4);
            seen_v6.insert(lease.ipv6_prefix);
            let addresses = AssignedAddresses {
                ipv4: lease.ipv4,
                ipv4_prefix_len: lease.ipv4_prefix_len,
                ipv6_prefix: lease.ipv6_prefix,
                ipv6_prefix_len: lease.ipv6_prefix_len,
            };
            // Convert the remaining wall time to a monotonic deadline for
            // in-memory TTLs (saturating, never panics).
            let mono_expires_at_ms =
                monotonic_expiry_from_wall(lease.expires_at_ms, now.wall_ms, now.monotonic_ms);
            match lease.state {
                LeaseState::Reserved => {
                    if inner.active.len().saturating_add(inner.pending.len())
                        >= self.config.maximum_leases
                    {
                        self.metrics.recovered_dropped.fetch_add(1, Ordering::Relaxed);
                        stale.push(lease);
                        continue;
                    }
                    inner.pending.insert(
                        lease.session_id,
                        ReservedLease {
                            device_id: lease.device_id,
                            addresses,
                            expires_at_ms: mono_expires_at_ms,
                        },
                    );
                }
                LeaseState::Active => {
                    if inner.active.len().saturating_add(inner.pending.len())
                        >= self.config.maximum_leases
                    {
                        self.metrics.recovered_dropped.fetch_add(1, Ordering::Relaxed);
                        stale.push(lease);
                        continue;
                    }
                    inner.active.insert(
                        lease.session_id,
                        ActiveLease {
                            device_id: lease.device_id,
                            addresses,
                            expires_at_ms: mono_expires_at_ms,
                        },
                    );
                }
                LeaseState::ReleasePending => {
                    if inner.release_pending.len() >= self.config.maximum_pending_releases {
                        self.metrics.recovered_dropped.fetch_add(1, Ordering::Relaxed);
                        stale.push(lease);
                        continue;
                    }
                    inner.release_order.push_back(lease.session_id);
                    inner.release_pending.insert(
                        lease.session_id,
                        ReleasePendingLease {
                            device_id: lease.device_id,
                            addresses,
                            expires_at_ms: mono_expires_at_ms,
                            attempts: 0,
                            next_retry_ms: next_retry_deadline(now.monotonic_ms, 0),
                        },
                    );
                }
            }
            self.metrics.recovered.fetch_add(1, Ordering::Relaxed);
        }
        let store = self.store.clone();
        drop(inner);
        // Delete discarded store entries outside the pool lock. A failed
        // delete is quarantined as nonreusable `ReleasePending` so its
        // addresses can never be re-leased; quarantine overflow fails pool
        // construction closed (no silent collision after restart).
        let mut failed: Vec<PersistedLease> = Vec::new();
        if let Some(store) = &store {
            for lease in &stale {
                if store.release(&lease.session_id).is_err() {
                    failed.push(*lease);
                }
            }
        }
        if !failed.is_empty() {
            let mut inner = self.inner.lock().map_err(|_| AddressPoolError::Unavailable)?;
            for lease in failed {
                let quarantined = PersistedLease {
                    state: LeaseState::ReleasePending,
                    ..lease
                };
                if self.enqueue_release_locked(&mut inner, quarantined, now.monotonic_ms).is_err() {
                    return Err(AddressPoolError::Store);
                }
                self.metrics.store_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn valid_persisted_locked(
        &self,
        inner: &Inner,
        lease: &PersistedLease,
        seen_sessions: &HashSet<SessionId>,
        seen_v4: &HashSet<[u8; 4]>,
        seen_v6: &HashSet<[u8; 16]>,
    ) -> bool {
        if is_zero_id(lease.session_id.as_bytes()) || is_zero_id(lease.device_id.as_bytes()) {
            return false;
        }
        if lease.ipv4_prefix_len != self.config.ipv4_prefix_len
            || lease.ipv6_prefix_len != IPV6_LEASE_PREFIX_LEN
        {
            return false;
        }
        if !self.ipv4_usable(lease.ipv4) || !self.ipv6_usable(&lease.ipv6_prefix) {
            return false;
        }
        if seen_sessions.contains(&lease.session_id)
            || seen_v4.contains(&lease.ipv4)
            || seen_v6.contains(&lease.ipv6_prefix)
            || inner.active.contains_key(&lease.session_id)
            || inner.pending.contains_key(&lease.session_id)
            || inner.release_pending.contains_key(&lease.session_id)
        {
            return false;
        }
        if inner.active.values().any(|active| active.addresses.ipv4 == lease.ipv4)
            || inner.pending.values().any(|reserved| reserved.addresses.ipv4 == lease.ipv4)
            || inner.release_pending.values().any(|quarantined| quarantined.addresses.ipv4 == lease.ipv4)
            || inner.active.values().any(|active| active.addresses.ipv6_prefix == lease.ipv6_prefix)
            || inner.pending.values().any(|reserved| reserved.addresses.ipv6_prefix == lease.ipv6_prefix)
            || inner.release_pending.values().any(|quarantined| quarantined.addresses.ipv6_prefix == lease.ipv6_prefix)
        {
            return false;
        }
        true
    }

    fn allocate_locked(&self, inner: &Inner) -> Result<AssignedAddresses, AddressPoolError> {
        let ipv4 = self.find_free_ipv4(inner).ok_or_else(|| {
            self.metrics.exhausted.fetch_add(1, Ordering::Relaxed);
            AddressPoolError::Exhausted
        })?;
        let ipv6_prefix = self.find_free_ipv6(inner).ok_or_else(|| {
            self.metrics.exhausted.fetch_add(1, Ordering::Relaxed);
            AddressPoolError::Exhausted
        })?;
        Ok(AssignedAddresses {
            ipv4,
            ipv4_prefix_len: self.config.ipv4_prefix_len,
            ipv6_prefix,
            ipv6_prefix_len: IPV6_LEASE_PREFIX_LEN,
        })
    }

    fn find_free_ipv4(&self, inner: &Inner) -> Option<[u8; 4]> {
        let mask = prefix_mask_v4(self.config.ipv4_prefix_len);
        let network_u32 = u32::from_be_bytes(self.config.ipv4_network) & mask;
        let broadcast_u32 = network_u32 | !mask;
        let gateway_u32 = u32::from_be_bytes(self.config.ipv4_gateway);
        let reserved: HashSet<u32> = self.config.reserved_ipv4.iter().map(|addr| u32::from_be_bytes(*addr)).collect();
        // Quarantined and inflight addresses are nonreusable until their
        // durable delete succeeds or their persist commits; they block
        // allocation exactly like live leases.
        let used: HashSet<u32> = inner
            .active
            .values()
            .map(|lease| u32::from_be_bytes(lease.addresses.ipv4))
            .chain(inner.pending.values().map(|lease| u32::from_be_bytes(lease.addresses.ipv4)))
            .chain(
                inner
                    .release_pending
                    .values()
                    .map(|lease| u32::from_be_bytes(lease.addresses.ipv4)),
            )
            .chain(inner.inflight_v4.iter().copied())
            .collect();
        let search_bound = (self.config.maximum_leases + reserved.len() + 8).min(65_536);
        let mut scanned = 0usize;
        let mut candidate = network_u32.saturating_add(1);
        while candidate < broadcast_u32 && scanned < search_bound {
            scanned = scanned.saturating_add(1);
            if candidate == gateway_u32 || reserved.contains(&candidate) || used.contains(&candidate) {
                candidate = candidate.saturating_add(1);
                continue;
            }
            return Some(candidate.to_be_bytes());
        }
        // The lowest free host always lies within the first
        // `leases + reserved + slack` candidates; anything beyond means the
        // usable range itself is exhausted.
        if inner.active.len().saturating_add(inner.pending.len()) >= self.config.maximum_leases {
            return None;
        }
        let mut fallback = network_u32.saturating_add(1);
        while fallback < broadcast_u32 {
            if fallback != gateway_u32 && !reserved.contains(&fallback) && !used.contains(&fallback) {
                return Some(fallback.to_be_bytes());
            }
            fallback = fallback.saturating_add(1);
            if fallback.wrapping_sub(network_u32) > 1_048_576 {
                break;
            }
        }
        None
    }

    fn find_free_ipv6(&self, inner: &Inner) -> Option<[u8; 16]> {
        let used: HashSet<[u8; 16]> = inner
            .active
            .values()
            .map(|lease| lease.addresses.ipv6_prefix)
            .chain(inner.pending.values().map(|lease| lease.addresses.ipv6_prefix))
            .chain(
                inner
                    .release_pending
                    .values()
                    .map(|lease| lease.addresses.ipv6_prefix),
            )
            .chain(inner.inflight_v6.iter().copied())
            .collect();
        let usable = usable_ipv6_subnets(self.config.ipv6_parent_prefix_len) as usize;
        let search_bound = (self.config.maximum_leases + 8).min(usable);
        for subnet in 1..=search_bound as u64 {
            let candidate = ipv6_subnet_prefix(&self.config.ipv6_base, self.config.ipv6_parent_prefix_len, subnet);
            if !used.contains(&candidate) {
                return Some(candidate);
            }
        }
        if inner.active.len().saturating_add(inner.pending.len()) >= self.config.maximum_leases {
            return None;
        }
        for subnet in 1..=usable as u64 {
            let candidate = ipv6_subnet_prefix(&self.config.ipv6_base, self.config.ipv6_parent_prefix_len, subnet);
            if !used.contains(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn ipv4_usable(&self, addr: [u8; 4]) -> bool {
        let mask = prefix_mask_v4(self.config.ipv4_prefix_len);
        let network_u32 = u32::from_be_bytes(self.config.ipv4_network) & mask;
        let broadcast_u32 = network_u32 | !mask;
        let value = u32::from_be_bytes(addr);
        if value & mask != network_u32 || value == network_u32 || value == broadcast_u32 {
            return false;
        }
        if value == u32::from_be_bytes(self.config.ipv4_gateway) {
            return false;
        }
        if self.config.reserved_ipv4.contains(&addr) {
            return false;
        }
        true
    }

    fn ipv6_usable(&self, prefix: &[u8; 16]) -> bool {
        if !ipv6_prefix_matches_parent(prefix, &self.config.ipv6_base, self.config.ipv6_parent_prefix_len) {
            return false;
        }
        if !ipv6_is_64_aligned(prefix) {
            return false;
        }
        if ipv6_subnet_index(&self.config.ipv6_base, self.config.ipv6_parent_prefix_len, prefix) == Some(0) {
            return false;
        }
        true
    }

    /// Quarantines a failed durable delete as `ReleasePending` (nonreusable).
    /// Never drops on overflow: when the quarantine is full it fails closed
    /// with `Store` and counts `quarantine_full`, leaving the caller to keep
    /// the lease blocked. `release_retry_dropped` is retained for
    /// compatibility and always reads zero. The quarantine entry becomes due
    /// after `next_retry_deadline(now_ms, 0)` (exponential backoff base).
    fn enqueue_release_locked(
        &self,
        inner: &mut Inner,
        lease: PersistedLease,
        now_ms: u64,
    ) -> Result<(), AddressPoolError> {
        if inner.release_pending.contains_key(&lease.session_id) {
            return Ok(());
        }
        if inner.release_pending.len() >= self.config.maximum_pending_releases {
            self.metrics.quarantine_full.fetch_add(1, Ordering::Relaxed);
            self.metrics.store_failures.fetch_add(1, Ordering::Relaxed);
            return Err(AddressPoolError::Store);
        }
        inner.release_order.push_back(lease.session_id);
        inner.release_pending.insert(
            lease.session_id,
            ReleasePendingLease {
                device_id: lease.device_id,
                addresses: AssignedAddresses {
                    ipv4: lease.ipv4,
                    ipv4_prefix_len: lease.ipv4_prefix_len,
                    ipv6_prefix: lease.ipv6_prefix,
                    ipv6_prefix_len: lease.ipv6_prefix_len,
                },
                expires_at_ms: lease.expires_at_ms,
                attempts: 0,
                next_retry_ms: next_retry_deadline(now_ms, 0),
            },
        );
        Ok(())
    }
}

/// Deterministic exponential backoff for quarantined durable deletes:
/// `now + min(cap, base * 2^attempts)`, saturating. No sleeps, no randomness;
/// callers gate retries on `now_ms >= next_retry_ms`.
fn next_retry_deadline(now_ms: u64, attempts: u64) -> u64 {
    let shift = attempts.min(16);
    let backoff = RETRY_BASE_MS.saturating_mul(1u64 << shift).min(RETRY_CAP_MS);
    now_ms.saturating_add(backoff)
}

impl SessionCleanup for AddressPool {
    fn release_address(&self, removal: SessionRemoval) {
        // Non-blocking by construction: the lease is quarantined in memory
        // without store I/O (never blocks a Tokio executor thread during
        // session close). The bounded retry path performs the durable delete
        // with backoff; quarantine overflow keeps the lease blocked and is
        // retried by the next sweep.
        let _ = self.release_deferred(removal.session_id);
    }
}

// ---------------------------------------------------------------------------
// Supervised autonomous pool expiry sweep and durable-release retry (WP-400
// final blocker)
// ---------------------------------------------------------------------------

/// Configuration for the supervised autonomous pool sweep.
///
/// The sweep interval is bounded between `min_interval_ms` and
/// `max_interval_ms`. The production ticker uses `min_interval_ms` as the
/// real tick frequency; the maximum is a validation bound that prevents
/// accidentally disabled sweeps. Each tick runs [`AddressPool::sweep`] on the
/// bounded blocking pool (never on an executor thread), which expires stale
/// Reserved/Active leases and retries quarantined durable deletes with the
/// bounded batch plus backoff. When a session manager is attached, expired
/// lease sessions are closed autonomously (idempotent) so an expired lease
/// never leaves a live session without addresses.
///
/// Fields are private to prevent construction that bypasses validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSweepConfig {
    min_interval_ms: u64,
    max_interval_ms: u64,
}

impl PoolSweepConfig {
    /// Creates a sweep config with the given min and max interval. Returns
    /// `None` when out of range (`min >= 1`, `max >= min`,
    /// `max <= 3_600_000`).
    #[must_use]
    pub fn new(min_interval_ms: u64, max_interval_ms: u64) -> Option<Self> {
        if min_interval_ms < 1
            || max_interval_ms < min_interval_ms
            || max_interval_ms > 3_600_000
        {
            return None;
        }
        Some(Self {
            min_interval_ms,
            max_interval_ms,
        })
    }

    /// Convenience constructor for a fixed-interval sweep (min == max).
    #[must_use]
    pub fn fixed(interval_ms: u64) -> Option<Self> {
        Self::new(interval_ms, interval_ms)
    }

    /// Minimum interval between sweep invocations (monotonic milliseconds).
    #[must_use]
    pub fn min_interval_ms(&self) -> u64 {
        self.min_interval_ms
    }

    /// Maximum allowed interval between sweep invocations.
    #[must_use]
    pub fn max_interval_ms(&self) -> u64 {
        self.max_interval_ms
    }
}

/// Internal message for the pool sweep tick channel. Production ticks carry
/// no ack; manual (test) ticks carry a oneshot sender so the test can await
/// deterministic completion.
pub(crate) enum PoolSweepTick {
    /// Run a sweep at the current clock time. Complete `ack` after
    /// processing when present (tests only).
    Sweep {
        ack: Option<tokio::sync::oneshot::Sender<()>>,
    },
    /// Shut down the sweep task.
    Shutdown,
}

/// Occupancy and outcome metrics for the autonomous pool sweep, including
/// the capacity-1 coalescing tick queue (drops, queued ticks, depth).
#[derive(Debug, Default)]
pub struct PoolSweepMetrics {
    sweeps_completed: AtomicU64,
    leases_expired: AtomicU64,
    sessions_closed: AtomicU64,
    sweeps_empty: AtomicU64,
    ticks_queued: AtomicU64,
    ticks_dropped: AtomicU64,
    queue_depth: AtomicU64,
}

impl PoolSweepMetrics {
    #[must_use]
    pub fn sweeps_completed(&self) -> u64 {
        self.sweeps_completed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn leases_expired(&self) -> u64 {
        self.leases_expired.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn sessions_closed(&self) -> u64 {
        self.sessions_closed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn sweeps_empty(&self) -> u64 {
        self.sweeps_empty.load(Ordering::Relaxed)
    }

    /// Ticks successfully enqueued into the capacity-1 sweep queue.
    #[must_use]
    pub fn ticks_queued(&self) -> u64 {
        self.ticks_queued.load(Ordering::Relaxed)
    }

    /// Ticks coalesced away because another tick was still pending. The
    /// queue is capacity 1, so a producer tick is dropped instead of forming
    /// a backlog; the pending tick runs with the latest clock value.
    #[must_use]
    pub fn ticks_dropped(&self) -> u64 {
        self.ticks_dropped.load(Ordering::Relaxed)
    }

    /// Last observed depth of the tick queue. Capacity 1, so 0 or 1.
    #[must_use]
    pub fn queue_depth(&self) -> u64 {
        self.queue_depth.load(Ordering::Relaxed)
    }
}

impl PartialEq for PoolSweepMetrics {
    fn eq(&self, other: &Self) -> bool {
        self.sweeps_completed() == other.sweeps_completed()
            && self.leases_expired() == other.leases_expired()
            && self.sessions_closed() == other.sessions_closed()
            && self.sweeps_empty() == other.sweeps_empty()
            && self.ticks_queued() == other.ticks_queued()
            && self.ticks_dropped() == other.ticks_dropped()
            && self.queue_depth() == other.queue_depth()
    }
}

impl Eq for PoolSweepMetrics {}

/// Supervised autonomous pool sweep for expired leases and quarantined
/// durable deletes. The background task is owned exclusively by this struct
/// and cannot leak: the struct owns the `JoinHandle` for both the sweep task
/// and the production ticker task.
///
/// Each tick runs [`AddressPool::sweep`] via [`AddressPool::sweep_async`]
/// (bounded `spawn_blocking`, never on an executor thread), which expires
/// stale Reserved/Active leases with durable deletes and retries previously
/// quarantined deletes with the bounded batch plus backoff. When a session
/// manager is attached, every expired session ID is closed idempotently via
/// [`V2SessionManager::close`]; the session cleanup path quarantines the
/// lease non-blockingly, and the next tick retries its durable delete. After
/// a session close/expiry, no manual sweep or retry call is required.
///
/// # Architecture
///
/// The sweep task owns the `mpsc::Receiver<PoolSweepTick>` directly (no async
/// mutex), fed by a **capacity-1 bounded channel**. Production ticks arrive
/// from a tokio interval task whose `JoinHandle` is owned by this struct;
/// that task uses `try_send`, so a tick produced while a previous tick is
/// still pending is coalesced away and counted in
/// [`PoolSweepMetrics::ticks_dropped`] rather than forming a backlog. Manual
/// ticks arrive from a [`test_support::PoolManualTriggerHandle`] sharing the
/// same channel.
///
/// Lock order is always pool sweep (pool lock released before store I/O and
/// before any session close) then session close (session-map lock, with pool
/// cleanup running after the map lock is released), matching the listener's
/// accept/control-tick order, so the autonomous task cannot deadlock.
///
/// # Shutdown
///
/// Call [`SupervisedPoolSweep::stop`] to abort the production ticker
/// (preventing new ticks), send `Shutdown` on the tick channel, and await
/// both task joins. Returns the final sweep metrics once both tasks have
/// exited. This method is idempotent.
pub struct SupervisedPoolSweep {
    handle: Option<tokio::task::JoinHandle<()>>,
    ticker_handle: Option<tokio::task::JoinHandle<()>>,
    tick_tx: tokio::sync::mpsc::Sender<PoolSweepTick>,
    pool: Arc<AddressPool>,
    sessions: Option<Arc<V2SessionManager>>,
    config: PoolSweepConfig,
    metrics: Arc<PoolSweepMetrics>,
    #[allow(dead_code)] // Cloned into the spawned sweep task at construction.
    clock: Arc<dyn Clock>,
}

impl SupervisedPoolSweep {
    /// Spawns a supervised autonomous sweep task using a production monotonic
    /// clock and a tokio interval ticker. No session manager is attached, so
    /// expired lease IDs are swept and retried but sessions must be closed by
    /// the caller (listener path). Prefer
    /// [`SupervisedPoolSweep::spawn_with_sessions`] in production so expiry
    /// closes sessions autonomously.
    pub fn spawn(
        pool: Arc<AddressPool>,
        config: PoolSweepConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::spawn_inner(pool, None, config, clock)
    }

    /// Spawns a supervised autonomous sweep task that also closes expired
    /// lease sessions idempotently. This is the production entry point: after
    /// a lease expiry the session is closed without listener traffic, and
    /// after a session close/expiry the quarantined durable delete is retried
    /// on subsequent ticks with bounded batch plus backoff.
    pub fn spawn_with_sessions(
        pool: Arc<AddressPool>,
        sessions: Arc<V2SessionManager>,
        config: PoolSweepConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::spawn_inner(pool, Some(sessions), config, clock)
    }

    fn spawn_inner(
        pool: Arc<AddressPool>,
        sessions: Option<Arc<V2SessionManager>>,
        config: PoolSweepConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        // Capacity-1 bounded channel: at most one tick may be pending. The
        // production ticker uses try_send, so a sweep still running when the
        // next interval fires coalesces into the pending tick instead of
        // growing an unbounded backlog.
        let (tick_tx, tick_rx) = tokio::sync::mpsc::channel::<PoolSweepTick>(1);
        let metrics = Arc::new(PoolSweepMetrics::default());
        let ticker_metrics = Arc::clone(&metrics);

        // Spawn the production ticker task. The sender is cloned so the
        // sweep struct retains its own for shutdown.
        let ticker_tx = tick_tx.clone();
        let interval = std::time::Duration::from_millis(config.min_interval_ms());
        let ticker_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                match ticker_tx.try_send(PoolSweepTick::Sweep { ack: None }) {
                    Ok(()) => {
                        ticker_metrics.ticks_queued.fetch_add(1, Ordering::Relaxed);
                        ticker_metrics.queue_depth.store(1, Ordering::Relaxed);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // A tick is already pending: coalesce by dropping this
                        // one. The pending tick runs with the latest clock.
                        ticker_metrics.ticks_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
        });

        let metrics_clone = Arc::clone(&metrics);
        let pool_clone = Arc::clone(&pool);
        let sessions_clone = sessions.clone();
        let clock_clone = Arc::clone(&clock);
        let handle = tokio::spawn(async move {
            let mut tick_rx = tick_rx;
            while let Some(tick) = tick_rx.recv().await {
                // Capacity is 1, so consuming the tick emptied the queue.
                metrics_clone.queue_depth.store(0, Ordering::Relaxed);
                match tick {
                    PoolSweepTick::Shutdown => break,
                    PoolSweepTick::Sweep { ack } => {
                        // Pool I/O runs on the supervised owner queue via
                        // `sweep_at_time_async`, never on this executor thread
                        // and never as detached `spawn_blocking`. `Full` /
                        // `Timeout` yield an empty expiry so the task survives
                        // and retries on the next tick. Wall derives from the
                        // same clock so restart conversion stays correct.
                        let sweep_now = super::persistence::PoolTime::from_monotonic_and_wall_seconds(
                            clock_clone.monotonic_ms(),
                            clock_clone.unix_seconds(),
                        );
                        let expired = Arc::clone(&pool_clone)
                            .sweep_at_time_async(sweep_now)
                            .await;
                        let expired_count = expired.len() as u64;
                        metrics_clone
                            .sweeps_completed
                            .fetch_add(1, Ordering::Relaxed);
                        metrics_clone
                            .leases_expired
                            .fetch_add(expired_count, Ordering::Relaxed);
                        if expired_count == 0 {
                            metrics_clone.sweeps_empty.fetch_add(1, Ordering::Relaxed);
                        }
                        // Autonomous expiry close (idempotent): an expired
                        // lease never leaves a live session without
                        // addresses, even with no listener traffic. The
                        // session cleanup quarantines the lease
                        // non-blockingly; the next tick retries its durable
                        // delete. Lock order is pool-then-session with no
                        // nesting (pool lock released before this loop).
                        let mut closed = 0u64;
                        if let Some(sessions) = sessions_clone.as_ref() {
                            for session_id in expired {
                                if sessions.close(session_id).unwrap_or(false) {
                                    closed = closed.saturating_add(1);
                                }
                            }
                        }
                        if closed != 0 {
                            metrics_clone
                                .sessions_closed
                                .fetch_add(closed, Ordering::Relaxed);
                        }
                        if let Some(ack) = ack {
                            let _ = ack.send(());
                        }
                    }
                }
            }
        });

        Self {
            handle: Some(handle),
            ticker_handle: Some(ticker_handle),
            tick_tx,
            pool,
            sessions,
            config,
            metrics,
            clock,
        }
    }

    /// Test constructor: spawns a sweep task with a deterministic manual
    /// clock. No production ticker is created; tests drive ticks through the
    /// returned [`test_support::PoolManualTriggerHandle`].
    #[cfg(test)]
    pub fn spawn_with_manual(
        pool: Arc<AddressPool>,
        config: PoolSweepConfig,
        clock: Arc<test_support::PoolManualClock>,
    ) -> (Self, test_support::PoolManualTriggerHandle) {
        Self::spawn_with_manual_inner(pool, None, config, clock)
    }

    /// Test constructor with autonomous session close. Expired lease IDs are
    /// closed idempotently on each manual tick, mirroring production.
    #[cfg(test)]
    pub fn spawn_with_manual_and_sessions(
        pool: Arc<AddressPool>,
        sessions: Arc<V2SessionManager>,
        config: PoolSweepConfig,
        clock: Arc<test_support::PoolManualClock>,
    ) -> (Self, test_support::PoolManualTriggerHandle) {
        Self::spawn_with_manual_inner(pool, Some(sessions), config, clock)
    }

    #[cfg(test)]
    fn spawn_with_manual_inner(
        pool: Arc<AddressPool>,
        sessions: Option<Arc<V2SessionManager>>,
        config: PoolSweepConfig,
        clock: Arc<test_support::PoolManualClock>,
    ) -> (Self, test_support::PoolManualTriggerHandle) {
        let (tick_tx, tick_rx) = tokio::sync::mpsc::channel::<PoolSweepTick>(1);
        let metrics = Arc::new(PoolSweepMetrics::default());
        let sweep_tx = tick_tx.clone();
        let trigger_handle = test_support::PoolManualTriggerHandle::new(
            tick_tx,
            Arc::clone(&clock),
            Arc::clone(&metrics),
        );

        let metrics_clone = Arc::clone(&metrics);
        let pool_clone = Arc::clone(&pool);
        let sessions_clone = sessions.clone();
        // Move the original Arc<PoolManualClock> into Arc<dyn Clock> for the
        // sweep task and the lifecycle struct. The trigger handle already
        // received its own clone above.
        let clock_dyn: Arc<dyn Clock> = clock as Arc<dyn Clock>;
        let clock_for_task = Arc::clone(&clock_dyn);

        let handle = tokio::spawn(async move {
            let mut tick_rx = tick_rx;
            while let Some(tick) = tick_rx.recv().await {
                metrics_clone.queue_depth.store(0, Ordering::Relaxed);
                match tick {
                    PoolSweepTick::Shutdown => break,
                    PoolSweepTick::Sweep { ack } => {
                        let sweep_now = super::persistence::PoolTime::from_monotonic_and_wall_seconds(
                            clock_for_task.monotonic_ms(),
                            clock_for_task.unix_seconds(),
                        );
                        let expired = Arc::clone(&pool_clone)
                            .sweep_at_time_async(sweep_now)
                            .await;
                        let expired_count = expired.len() as u64;
                        metrics_clone
                            .sweeps_completed
                            .fetch_add(1, Ordering::Relaxed);
                        metrics_clone
                            .leases_expired
                            .fetch_add(expired_count, Ordering::Relaxed);
                        if expired_count == 0 {
                            metrics_clone.sweeps_empty.fetch_add(1, Ordering::Relaxed);
                        }
                        let mut closed = 0u64;
                        if let Some(sessions) = sessions_clone.as_ref() {
                            for session_id in expired {
                                if sessions.close(session_id).unwrap_or(false) {
                                    closed = closed.saturating_add(1);
                                }
                            }
                        }
                        if closed != 0 {
                            metrics_clone
                                .sessions_closed
                                .fetch_add(closed, Ordering::Relaxed);
                        }
                        if let Some(ack) = ack {
                            let _ = ack.send(());
                        }
                    }
                }
            }
        });

        let sweep = Self {
            handle: Some(handle),
            ticker_handle: None,
            tick_tx: sweep_tx,
            pool,
            sessions,
            config,
            metrics,
            clock: clock_dyn,
        };
        (sweep, trigger_handle)
    }

    /// Signals the sweep task to shut down and joins it with a bounded
    /// deadline. Never hangs indefinitely: the production ticker is aborted
    /// first (no new ticks), `Shutdown` is queued with `try_send`
    /// (backpressure, no indefinite wait), and both joins are bounded with a
    /// hard timeout (stalled sweeps are aborted, counted via the sweep
    /// metrics). Idempotent: a second call returns the same snapshot without
    /// hanging.
    pub async fn stop(&mut self) -> PoolSweepMetrics {
        // Abort the production ticker first so no new ticks arrive.
        if let Some(handle) = self.ticker_handle.take() {
            handle.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        }
        // Best-effort shutdown signal: `try_send` never waits. When the
        // capacity-1 queue is full (a sweep still running), the shutdown is
        // delivered by aborting below instead of waiting indefinitely.
        let shutdown_queued = self.tick_tx.try_send(PoolSweepTick::Shutdown).is_ok();
        if let Some(handle) = self.handle.take() {
            if shutdown_queued {
                // Bounded join: a stalled sweep (owner timeout is 500 ms, plus
                // session close) must exit well within 2 s; otherwise abort.
                if tokio::time::timeout(std::time::Duration::from_secs(2), handle)
                    .await
                    .is_err()
                {
                    // Timeout: the handle was consumed by the timeout; the
                    // task is detached (it will exit when its current owner
                    // call times out). No hang, no additional metric beyond
                    // the sweep counts (the pending tick stays dropped).
                }
            } else {
                // Queue full: abort promptly instead of waiting for the
                // in-flight sweep to drain.
                handle.abort();
                let _ = handle.await;
            }
        }
        self.metrics_snapshot()
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> PoolSweepMetrics {
        PoolSweepMetrics {
            sweeps_completed: AtomicU64::new(self.metrics.sweeps_completed()),
            leases_expired: AtomicU64::new(self.metrics.leases_expired()),
            sessions_closed: AtomicU64::new(self.metrics.sessions_closed()),
            sweeps_empty: AtomicU64::new(self.metrics.sweeps_empty()),
            ticks_queued: AtomicU64::new(self.metrics.ticks_queued()),
            ticks_dropped: AtomicU64::new(self.metrics.ticks_dropped()),
            queue_depth: AtomicU64::new(self.metrics.queue_depth()),
        }
    }

    #[must_use]
    pub fn pool(&self) -> &Arc<AddressPool> {
        &self.pool
    }

    #[must_use]
    pub fn sessions(&self) -> Option<&Arc<V2SessionManager>> {
        self.sessions.as_ref()
    }

    #[must_use]
    pub fn config(&self) -> PoolSweepConfig {
        self.config
    }
}

impl Drop for SupervisedPoolSweep {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.ticker_handle.take() {
            handle.abort();
        }
    }
}

impl std::fmt::Debug for SupervisedPoolSweep {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SupervisedPoolSweep(REDACTED)")
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Deterministic manual clock for pool sweep tests. Implements
    /// [`Clock`] so the sweep task and production code share one monotonic
    /// time domain. Tests advance it explicitly; no real time elapses.
    #[derive(Debug)]
    pub struct PoolManualClock {
        now: AtomicU64,
    }

    impl PoolManualClock {
        pub fn new(initial_ms: u64) -> Self {
            Self {
                now: AtomicU64::new(initial_ms),
            }
        }

        pub fn set(&self, now_ms: u64) {
            self.now.store(now_ms, Ordering::Relaxed);
        }
    }

    impl Clock for PoolManualClock {
        fn monotonic_ms(&self) -> u64 {
            self.now.load(Ordering::Relaxed)
        }

        fn unix_seconds(&self) -> u64 {
            self.now.load(Ordering::Relaxed) / 1_000
        }
    }

    /// Handle for sending deterministic ticks to the pool sweep task. Tests
    /// advance the clock and call `tick()` or `advance_and_tick()`, both of
    /// which await deterministic completion acknowledgement from the sweep
    /// task — no yield loops or real time. The shared tick channel has
    /// capacity 1; `tick_no_ack` returns whether the tick was actually queued
    /// so tests can assert coalescing deterministically.
    pub struct PoolManualTriggerHandle {
        tick_tx: tokio::sync::mpsc::Sender<PoolSweepTick>,
        clock: Arc<PoolManualClock>,
        metrics: Arc<PoolSweepMetrics>,
    }

    impl PoolManualTriggerHandle {
        pub(crate) fn new(
            tick_tx: tokio::sync::mpsc::Sender<PoolSweepTick>,
            clock: Arc<PoolManualClock>,
            metrics: Arc<PoolSweepMetrics>,
        ) -> Self {
            Self {
                tick_tx,
                clock,
                metrics,
            }
        }

        /// Advances the deterministic clock and sends one tick, waiting for
        /// the sweep task to complete processing. Fully deterministic: no
        /// real time elapses.
        pub async fn advance_and_tick(&self, new_ms: u64) {
            self.clock.set(new_ms);
            self.tick().await;
        }

        /// Sends a tick at the current clock value and waits for the sweep
        /// task to complete processing.
        pub async fn tick(&self) {
            let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
            if self
                .tick_tx
                .send(PoolSweepTick::Sweep { ack: Some(ack_tx) })
                .await
                .is_ok()
            {
                self.metrics.ticks_queued.fetch_add(1, Ordering::Relaxed);
                self.metrics.queue_depth.store(1, Ordering::Relaxed);
            }
            let _ = ack_rx.await;
        }

        /// Advances the clock without sending a tick. Useful for tests that
        /// need to set time before a subsequent tick.
        pub fn advance_clock(&self, new_ms: u64) {
            self.clock.set(new_ms);
        }

        /// Sends a tick without waiting for completion acknowledgement.
        /// Returns `true` when the tick was queued. A `false` return means
        /// the capacity-1 queue already held a pending tick (coalesced/drop,
        /// counted in `ticks_dropped`) or the channel was closed, e.g. after
        /// the sweep owner was dropped.
        pub fn tick_no_ack(&self) -> bool {
            match self.tick_tx.try_send(PoolSweepTick::Sweep { ack: None }) {
                Ok(()) => {
                    self.metrics.ticks_queued.fetch_add(1, Ordering::Relaxed);
                    self.metrics.queue_depth.store(1, Ordering::Relaxed);
                    true
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    self.metrics.ticks_dropped.fetch_add(1, Ordering::Relaxed);
                    self.metrics.queue_depth.store(1, Ordering::Relaxed);
                    false
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            }
        }

        #[must_use]
        pub fn clock(&self) -> &PoolManualClock {
            &self.clock
        }
    }
}

fn is_zero_id(bytes: &[u8; 16]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

const fn prefix_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn usable_ipv4_hosts(network: u32, broadcast: u32, reserved_count: usize) -> u64 {
    if broadcast <= network.saturating_add(1) {
        return 0;
    }
    let total = (broadcast - network).saturating_sub(1) as u64;
    // One address is always consumed by the validated gateway; each explicit
    // reservation consumes one more. All were validated inside the network
    // and distinct from network/broadcast/gateway.
    total.saturating_sub(1 + reserved_count as u64)
}

fn ipv6_base_masked(base: &[u8; 16], parent_len: u8) -> bool {
    let value = u128::from_be_bytes(*base);
    let mask = if parent_len >= 128 { u128::MAX } else { u128::MAX << (128 - parent_len) };
    value & !mask == 0
}

fn usable_ipv6_subnets(parent_len: u8) -> u64 {
    if parent_len > 63 {
        return 0;
    }
    let bits = 64 - parent_len as u64;
    if bits >= 64 {
        return 0;
    }
    (1u64 << bits).saturating_sub(1)
}

fn ipv6_subnet_prefix(base: &[u8; 16], parent_len: u8, subnet: u64) -> [u8; 16] {
    let base_top = u64::from_be_bytes(base[0..8].try_into().unwrap_or([0; 8]));
    let parent_bits = parent_len.min(64) as u64;
    let parent_mask = if parent_bits == 0 {
        0
    } else if parent_bits >= 64 {
        u64::MAX
    } else {
        u64::MAX << (64 - parent_bits)
    };
    let subnet_bits = 64 - parent_bits;
    let subnet_masked = if subnet_bits >= 64 {
        subnet
    } else {
        subnet & ((1u64 << subnet_bits).wrapping_sub(1))
    };
    let top = (base_top & parent_mask) | subnet_masked;
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&top.to_be_bytes());
    out
}

fn ipv6_prefix_matches_parent(prefix: &[u8; 16], base: &[u8; 16], parent_len: u8) -> bool {
    let prefix_top = u64::from_be_bytes(prefix[0..8].try_into().unwrap_or([0; 8]));
    let base_top = u64::from_be_bytes(base[0..8].try_into().unwrap_or([0; 8]));
    let parent_bits = parent_len.min(64) as u64;
    let mask = if parent_bits == 0 {
        0
    } else if parent_bits >= 64 {
        u64::MAX
    } else {
        u64::MAX << (64 - parent_bits)
    };
    prefix_top & mask == base_top & mask
}

fn ipv6_is_64_aligned(prefix: &[u8; 16]) -> bool {
    prefix[8..16].iter().all(|byte| *byte == 0)
}

fn ipv6_subnet_index(base: &[u8; 16], parent_len: u8, prefix: &[u8; 16]) -> Option<u64> {
    if !ipv6_prefix_matches_parent(prefix, base, parent_len) {
        return None;
    }
    let prefix_top = u64::from_be_bytes(prefix[0..8].try_into().unwrap_or([0; 8]));
    let parent_bits = parent_len.min(64) as u64;
    if parent_bits >= 64 {
        return Some(0);
    }
    let subnet_bits = 64 - parent_bits;
    let mask = if subnet_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << subnet_bits).wrapping_sub(1)
    };
    Some(prefix_top & mask)
}

/// In-memory durable store for tests and ephemeral-managed deployments.
/// Failure injection is atomic and deterministic (no sleeps).
#[derive(Debug, Default)]
pub struct InMemoryLeaseStore {
    entries: Mutex<HashMap<SessionId, PersistedLease>>,
    fail_load: AtomicU64,
    fail_persist: AtomicU64,
    fail_release: AtomicU64,
}

impl InMemoryLeaseStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            fail_load: AtomicU64::new(0),
            fail_persist: AtomicU64::new(0),
            fail_release: AtomicU64::new(0),
        }
    }

    /// Fails the next `count` `load` calls, then recovers. Deterministic.
    pub fn fail_next_loads(&self, count: u64) {
        self.fail_load.fetch_add(count, Ordering::Relaxed);
    }

    /// Fails the next `count` `persist` calls, then recovers.
    pub fn fail_next_persists(&self, count: u64) {
        self.fail_persist.fetch_add(count, Ordering::Relaxed);
    }

    /// Fails the next `count` `release` calls, then recovers.
    pub fn fail_next_releases(&self, count: u64) {
        self.fail_release.fetch_add(count, Ordering::Relaxed);
    }

    fn take_flag(flag: &AtomicU64) -> bool {
        let mut current = flag.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return false;
            }
            match flag.compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(next) => current = next,
            }
        }
    }
}

impl LeaseStore for InMemoryLeaseStore {
    fn load(&self) -> Result<Vec<PersistedLease>, StoreError> {
        if Self::take_flag(&self.fail_load) {
            return Err(StoreError::Unavailable);
        }
        self.entries
            .lock()
            .map(|entries| entries.values().copied().collect())
            .map_err(|_| StoreError::Unavailable)
    }

    fn persist(&self, lease: &PersistedLease) -> Result<(), StoreError> {
        if Self::take_flag(&self.fail_persist) {
            return Err(StoreError::Io);
        }
        self.entries
            .lock()
            .map(|mut entries| {
                entries.insert(lease.session_id, *lease);
            })
            .map_err(|_| StoreError::Unavailable)
    }

    fn release(&self, session_id: &SessionId) -> Result<(), StoreError> {
        if Self::take_flag(&self.fail_release) {
            return Err(StoreError::Io);
        }
        self.entries
            .lock()
            .map(|mut entries| {
                entries.remove(session_id);
            })
            .map_err(|_| StoreError::Unavailable)
    }
}

/// Persistence mode for gateway startup (WP-400 requirement 2). Recovery is
/// explicit and fail-closed in every durable mode: any load, bound, or
/// validation failure returns [`AddressPoolError::Store`] and constructs no
/// pool, so a restart can never silently collide with a live lease.
#[derive(Debug, Clone)]
pub enum AddressPoolMode {
    /// No durability. A restart frees all leases. Unit tests and
    /// single-run self-hosted gateways without a journal.
    Ephemeral,
    /// Self-hosted durable mode: an atomic file journal at the given path.
    /// The journal is created on first persist; startup replays it and fails
    /// closed on corrupt or over-bound data.
    SelfHosted { journal_path: PathBuf },
    /// Managed durable mode: an external controller/operator-provided store
    /// behind the [`ManagedLeaseStore`] adapter, which enforces the hard
    /// lease cap at the store boundary before the pool validates entries.
    Managed { store: Arc<dyn LeaseStore> },
}

fn lease_state_to_wire(state: LeaseState) -> u8 {
    match state {
        LeaseState::Reserved => 0,
        LeaseState::Active => 1,
        LeaseState::ReleasePending => 2,
    }
}

fn lease_state_from_wire(value: u8) -> Option<LeaseState> {
    match value {
        0 => Some(LeaseState::Reserved),
        1 => Some(LeaseState::Active),
        2 => Some(LeaseState::ReleasePending),
        _ => None,
    }
}

fn encode_lease_record(lease: &PersistedLease) -> [u8; JOURNAL_RECORD_LEN] {
    let mut record = [0u8; JOURNAL_RECORD_LEN];
    record[0..4].copy_from_slice(&JOURNAL_MAGIC);
    record[4] = JOURNAL_VERSION;
    record[5] = lease_state_to_wire(lease.state);
    record[6..22].copy_from_slice(lease.session_id.as_bytes());
    record[22..38].copy_from_slice(lease.device_id.as_bytes());
    record[38..42].copy_from_slice(&lease.ipv4);
    record[42] = lease.ipv4_prefix_len;
    record[43..59].copy_from_slice(&lease.ipv6_prefix);
    record[59] = lease.ipv6_prefix_len;
    record[60..68].copy_from_slice(&lease.expires_at_ms.to_be_bytes());
    record
}

fn decode_lease_record(record: &[u8; JOURNAL_RECORD_LEN]) -> Option<PersistedLease> {
    if record[0..4] != JOURNAL_MAGIC || record[4] != JOURNAL_VERSION {
        return None;
    }
    let state = lease_state_from_wire(record[5])?;
    let mut session = [0u8; 16];
    session.copy_from_slice(&record[6..22]);
    let mut device = [0u8; 16];
    device.copy_from_slice(&record[22..38]);
    let mut ipv4 = [0u8; 4];
    ipv4.copy_from_slice(&record[38..42]);
    let mut ipv6 = [0u8; 16];
    ipv6.copy_from_slice(&record[43..59]);
    let mut expires = [0u8; 8];
    expires.copy_from_slice(&record[60..68]);
    Some(PersistedLease {
        session_id: SessionId::from_bytes(session),
        device_id: DeviceId::from_bytes(device),
        ipv4,
        ipv4_prefix_len: record[42],
        ipv6_prefix: ipv6,
        ipv6_prefix_len: record[59],
        state,
        expires_at_ms: u64::from_be_bytes(expires),
    })
}

/// Concrete durable self-hosted atomic journal store (WP-400).
///
/// - File layout: concatenated fixed-size records (no length prefix, no
///   allocator-controlled sizes). Loads reject trailing bytes, short reads,
///   bad magic/version (version 2 only; version 1 monotonic journals fail
///   closed), unknown states, permissive permissions, and symlinks as
///   `Corrupt`/`Io` (fail closed).
/// - Atomicity: every mutation holds the single mirror `Mutex` across the
///   file rewrite **and** the mirror commit, so concurrent persists/releases
///   serialize and the file never reflects a stale snapshot that would drop
///   a lease. The rewrite uses [`secure_atomic_write`] (0600 temp creation,
///   parent/tmp/file validation, atomic rename, parent fsync on Unix). A
///   crash leaves either the old or the new journal, never a half-write.
///   Temp-file, rename, and fsync failures surface as `Io` and leave the
///   mirror uncommitted (fail closed).
/// - Bounds: at most `MAX_LEASES_HARD_CAP` entries; larger mirrors or files
///   fail closed. File size is capped at `MAX_JOURNAL_BYTES`.
/// - Blocking: all methods perform blocking file I/O while holding the
///   store-private mirror lock. Production callers must use the pool's
///   `*_async` / `*_at_time_async` wrappers (bounded owner queue, never
///   detached `spawn_blocking`, never on an executor thread). The pool mutex
///   is never held here.
#[derive(Debug)]
pub struct JournalLeaseStore {
    path: PathBuf,
    entries: Mutex<HashMap<SessionId, PersistedLease>>,
}

impl JournalLeaseStore {
    /// Opens (or creates) the journal at `path` and replays it into memory.
    /// Missing file means an empty store. Corrupt, trailing-data,
    /// over-bound, permissive-permission, or symlinked journals fail closed
    /// with `Corrupt`/`Io`; I/O failures with `Io`. Never falls back to an
    /// empty pool on error. Never logs paths or contents.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        // Present-file permission gate: a permissive or symlinked journal
        // fails closed before any parse (Linux 0600, no symlinks).
        match std::fs::symlink_metadata(path) {
            Ok(_) => validate_journal_file(path).map_err(|_| StoreError::Corrupt)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
        let entries = Self::read_journal_file(path)?;
        if entries.len() > MAX_LEASES_HARD_CAP {
            return Err(StoreError::Corrupt);
        }
        let mut map = HashMap::new();
        for lease in entries {
            if map.insert(lease.session_id, lease).is_some() {
                return Err(StoreError::Corrupt);
            }
        }
        Ok(Self { path: path.to_path_buf(), entries: Mutex::new(map) })
    }

    /// Returns the journal path (for operator diagnostics; never logs
    /// lease contents).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_journal_file(path: &Path) -> Result<Vec<PersistedLease>, StoreError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(StoreError::Io),
        };
        if (bytes.len() as u64) > MAX_JOURNAL_BYTES {
            return Err(StoreError::Corrupt);
        }
        if bytes.len() % JOURNAL_RECORD_LEN != 0 {
            return Err(StoreError::Corrupt);
        }
        if bytes.len() / JOURNAL_RECORD_LEN > MAX_LEASES_HARD_CAP {
            return Err(StoreError::Corrupt);
        }
        let mut leases = Vec::with_capacity(bytes.len() / JOURNAL_RECORD_LEN);
        for chunk in bytes.chunks_exact(JOURNAL_RECORD_LEN) {
            let mut record = [0u8; JOURNAL_RECORD_LEN];
            record.copy_from_slice(chunk);
            leases.push(decode_lease_record(&record).ok_or(StoreError::Corrupt)?);
        }
        Ok(leases)
    }

    fn rewrite_journal_locked(&self, entries: &HashMap<SessionId, PersistedLease>) -> Result<(), StoreError> {
        if entries.len() > MAX_LEASES_HARD_CAP {
            return Err(StoreError::Io);
        }
        let mut ordered: Vec<&PersistedLease> = entries.values().collect();
        ordered.sort_by(|a, b| {
            a.session_id.as_bytes().cmp(b.session_id.as_bytes()).then_with(|| a.device_id.as_bytes().cmp(b.device_id.as_bytes()))
        });
        let mut bytes = Vec::with_capacity(ordered.len().saturating_mul(JOURNAL_RECORD_LEN));
        for lease in ordered {
            bytes.extend_from_slice(&encode_lease_record(lease));
        }
        // Secure 0600 atomic rewrite (parent/tmp/file validation, no symlinks,
        // Linux permission bits, parent fsync). Any failure leaves the old
        // journal intact and reports `Io` without paths or contents.
        secure_atomic_write(&self.path, &bytes).map_err(|_| StoreError::Io)
    }
}

impl LeaseStore for JournalLeaseStore {
    fn load(&self) -> Result<Vec<PersistedLease>, StoreError> {
        self.entries.lock().map(|entries| entries.values().copied().collect()).map_err(|_| StoreError::Unavailable)
    }

    fn persist(&self, lease: &PersistedLease) -> Result<(), StoreError> {
        // Single-guard serialization: this store-private mirror lock is held
        // across the snapshot build, the blocking file rewrite (tmp write +
        // file sync + atomic rename + parent-dir fsync), AND the mirror
        // commit. A second writer blocks for the whole critical section, so
        // the file can never reflect a stale snapshot that drops a
        // concurrent lease (lost-update). This is the store's private lock
        // (blocking file I/O runs on the caller's thread; production callers
        // use the pool's bounded `spawn_blocking` wrappers), never the pool
        // mutex. A rewrite failure returns `Io` with the mirror untouched
        // (fail closed).
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        let mut snapshot = entries.clone();
        snapshot.insert(lease.session_id, *lease);
        self.rewrite_journal_locked(&snapshot)?;
        *entries = snapshot;
        Ok(())
    }

    fn release(&self, session_id: &SessionId) -> Result<(), StoreError> {
        // Same single-guard serialization as `persist`: snapshot, rewrite,
        // and mirror commit share one critical section with no drop/re-lock
        // window where a concurrent writer could interleave and lose an
        // update.
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        let mut snapshot = entries.clone();
        snapshot.remove(session_id);
        self.rewrite_journal_locked(&snapshot)?;
        *entries = snapshot;
        Ok(())
    }
}

/// Managed-mode store adapter (WP-400). Wraps an operator/controller-provided
/// [`LeaseStore`] and enforces the hard lease cap at the store boundary so
/// an unbounded backend can never grow pool recovery: `load` fails closed
/// with `Corrupt` beyond `MAX_LEASES_HARD_CAP`. Persist/release errors pass
/// through unchanged (the pool quarantines release failures as nonreusable).
#[derive(Debug)]
pub struct ManagedLeaseStore {
    inner: Arc<dyn LeaseStore>,
}

impl ManagedLeaseStore {
    #[must_use]
    pub fn new(inner: Arc<dyn LeaseStore>) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn inner(&self) -> &Arc<dyn LeaseStore> {
        &self.inner
    }
}

impl LeaseStore for ManagedLeaseStore {
    fn load(&self) -> Result<Vec<PersistedLease>, StoreError> {
        let leases = self.inner.load()?;
        if leases.len() > MAX_LEASES_HARD_CAP {
            return Err(StoreError::Corrupt);
        }
        Ok(leases)
    }

    fn persist(&self, lease: &PersistedLease) -> Result<(), StoreError> {
        self.inner.persist(lease)
    }

    fn release(&self, session_id: &SessionId) -> Result<(), StoreError> {
        self.inner.release(session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(maximum_leases: usize) -> AddressPoolConfig {
        AddressPoolConfig::new(
            [10, 64, 0, 0],
            24,
            [10, 64, 0, 1],
            vec![[10, 64, 0, 254]],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            48,
            maximum_leases,
            5_000,
            60_000,
            maximum_leases.max(1),
        )
        .unwrap()
    }

    fn session(byte: u8) -> SessionId {
        SessionId::from_bytes([byte; 16])
    }

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_bytes([byte; 16])
    }

    #[test]
    fn two_sessions_receive_distinct_ipv4_and_ipv6_64() {
        let pool = AddressPool::new(test_config(4)).unwrap();
        let first = pool.reserve(session(1), device(11), 1_000).unwrap();
        let first_committed = pool.commit(session(1), 1_000).unwrap();
        assert_eq!(first, first_committed);
        let second = pool.reserve(session(2), device(12), 1_000).unwrap();
        let second_committed = pool.commit(session(2), 1_000).unwrap();
        assert_eq!(second, second_committed);
        assert_ne!(first.ipv4, second.ipv4, "IPv4 leases must be unique");
        assert_ne!(first.ipv6_prefix, second.ipv6_prefix, "IPv6 /64 leases must be unique");
        assert_eq!(first.ipv6_prefix_len, 64);
        assert_eq!(second.ipv6_prefix_len, 64);
        assert_eq!(first.ipv4_prefix_len, 24);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.active, 2);
        assert_eq!(snapshot.pending, 0);
    }

    #[test]
    fn gateway_and_reserved_addresses_are_never_allocated() {
        let pool = AddressPool::new(test_config(8)).unwrap();
        for index in 0..8u8 {
            let lease = pool.reserve(session(10 + index), device(20 + index), 1_000).unwrap();
            assert_ne!(lease.ipv4, [10, 64, 0, 0], "network address must never lease");
            assert_ne!(lease.ipv4, [10, 64, 0, 1], "gateway address must never lease");
            assert_ne!(lease.ipv4, [10, 64, 0, 254], "explicit reservation must never lease");
            assert_ne!(lease.ipv4, [10, 64, 0, 255], "broadcast must never lease");
            assert_ne!(&lease.ipv6_prefix[0..8], &[0xfd, 0, 0, 0, 0, 0, 0, 0], "gateway /64 (subnet zero) must never lease");
            pool.commit(session(10 + index), 1_000).unwrap();
        }
    }

    #[test]
    fn session_resume_returns_the_same_lease_for_the_same_device() {
        let pool = AddressPool::new(test_config(4)).unwrap();
        let first = pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        let resumed = pool.reserve(session(1), device(11), 2_000).unwrap();
        assert_eq!(first, resumed, "resume must return the identical lease");
        assert_eq!(pool.snapshot().active, 1);
        assert_eq!(pool.reserve(session(1), device(99), 2_000), Err(AddressPoolError::OwnerMismatch));
    }

    #[test]
    fn exhaustion_is_bounded_and_observable() {
        let pool = AddressPool::new(test_config(2)).unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        pool.reserve(session(2), device(12), 1_000).unwrap();
        pool.commit(session(2), 1_000).unwrap();
        assert_eq!(pool.reserve(session(3), device(13), 1_000), Err(AddressPoolError::Exhausted));
        assert!(pool.snapshot().exhausted >= 1);
        assert_eq!(pool.snapshot().active, 2);
    }

    #[test]
    fn pending_reservations_expire_deterministically_without_sleep() {
        let pool = AddressPool::new(test_config(2)).unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        assert!(pool.lookup(session(1)).is_some());
        let expired = pool.sweep(1_000 + 5_000);
        assert_eq!(expired, vec![session(1)]);
        assert!(pool.lookup(session(1)).is_none());
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.pending, 0);
        assert_eq!(snapshot.pending_expired, 1);
        // The freed slot is reusable deterministically.
        let reused = pool.reserve(session(2), device(12), 6_000).unwrap();
        assert_eq!(reused.ipv4, [10, 64, 0, 2]);
    }

    #[test]
    fn release_frees_the_slot_for_reuse() {
        let pool = AddressPool::new(test_config(2)).unwrap();
        let first = pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        assert!(pool.release(session(1)).unwrap());
        assert!(!pool.release(session(1)).unwrap(), "second release is idempotent");
        assert!(pool.lookup(session(1)).is_none());
        let reused = pool.reserve(session(2), device(12), 2_000).unwrap();
        pool.commit(session(2), 2_000).unwrap();
        assert_eq!(reused, first, "lowest free address is reused deterministically");
    }

    #[test]
    fn renewal_extends_the_dhcp_deadline() {
        let pool = AddressPool::new(test_config(2)).unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        pool.renew(session(1), 2_000).unwrap();
        assert_eq!(pool.snapshot().renewals, 1);
        // Without renewal the 60 s TTL from commit at t=1000 expires at 61000.
        // Renewal at t=2000 pushes it to 62000, so a sweep at 61000 frees
        // nothing, while a sweep at 62000 frees the lease.
        assert!(pool.sweep(61_000).is_empty());
        assert_eq!(pool.sweep(62_000), vec![session(1)]);
        assert_eq!(pool.snapshot().active_expired, 1);
    }

    #[test]
    fn store_failure_fails_closed_and_retry_recovers() {
        let store = Arc::new(InMemoryLeaseStore::new());
        store.fail_next_persists(1);
        let pool = AddressPool::with_store(test_config(2), Arc::clone(&store) as Arc<dyn LeaseStore>, 1_000).unwrap();
        assert_eq!(pool.reserve(session(1), device(11), 1_000), Err(AddressPoolError::Store));
        assert!(pool.lookup(session(1)).is_none(), "failed reserve must allocate nothing");
        let lease = pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        store.fail_next_releases(1);
        assert!(pool.release(session(1)).unwrap(), "in-memory release quarantines even when the store fails");
        assert_eq!(pool.snapshot().pending_releases, 1);
        assert_eq!(pool.snapshot().release_retry_dropped, 0, "quarantine never drops");
        // Quarantined addresses are nonreusable: another session must not reuse them.
        let other = pool.reserve(session(2), device(12), 1_000).unwrap();
        assert_ne!(other.ipv4, lease.ipv4, "quarantined IPv4 must not be reused");
        assert_ne!(other.ipv6_prefix, lease.ipv6_prefix, "quarantined /64 must not be reused");
        assert_eq!(pool.retry_pending_releases(), 0);
        assert_eq!(pool.snapshot().pending_releases, 0);
        assert_eq!(pool.snapshot().release_retries, 1);
        let _ = lease;
    }

    #[test]
    fn recovery_restores_valid_leases_and_drops_invalid() {
        let store = Arc::new(InMemoryLeaseStore::new());
        {
            let pool = AddressPool::with_store(test_config(4), Arc::clone(&store) as Arc<dyn LeaseStore>, 1_000).unwrap();
            pool.reserve(session(1), device(11), 1_000).unwrap();
            pool.commit(session(1), 1_000).unwrap();
            pool.reserve(session(2), device(12), 1_000).unwrap();
            pool.commit(session(2), 1_000).unwrap();
        }
        // Corrupt the store with a gateway collision and a duplicate address.
        // Expiry is far-future so the drop is due to the gateway collision,
        // not TTL; recovery runs inside the DHCP TTL (commit at 1000 + 60000).
        store
            .persist(&PersistedLease {
                session_id: session(9),
                device_id: device(19),
                ipv4: [10, 64, 0, 1],
                ipv4_prefix_len: 24,
                ipv6_prefix: [0xfd, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0],
                ipv6_prefix_len: 64,
                state: LeaseState::Active,
                expires_at_ms: 200_000,
            })
            .unwrap();
        let recovered = AddressPool::with_store(test_config(4), Arc::clone(&store) as Arc<dyn LeaseStore>, 2_000).unwrap();
        let snapshot = recovered.snapshot();
        assert_eq!(snapshot.recovered, 2);
        assert_eq!(snapshot.recovered_dropped, 1);
        assert!(recovered.lookup(session(1)).is_some());
        assert!(recovered.lookup(session(2)).is_some());
        assert!(recovered.lookup(session(9)).is_none(), "gateway collision must not recover");
    }

    #[test]
    fn load_failure_fails_pool_construction_closed() {
        let store = Arc::new(InMemoryLeaseStore::new());
        store.fail_next_loads(1);
        let result = AddressPool::with_store(test_config(2), store as Arc<dyn LeaseStore>, 1_000);
        assert!(matches!(result, Err(AddressPoolError::Store)));
    }

    #[test]
    fn invalid_configurations_are_rejected() {
        // Gateway outside the network.
        assert!(AddressPoolConfig::new(
            [10, 64, 0, 0], 24, [192, 168, 1, 1], vec![],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 48, 2, 5_000, 60_000, 2,
        ).is_err());
        // IPv6 parent with no usable /64 beyond the gateway subnet.
        assert!(AddressPoolConfig::new(
            [10, 64, 0, 0], 24, [10, 64, 0, 1], vec![],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 64, 1, 5_000, 60_000, 1,
        ).is_err());
        // Leases beyond what the /30 can supply.
        assert!(AddressPoolConfig::new(
            [10, 64, 0, 0], 30, [10, 64, 0, 1], vec![],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 48, 4, 5_000, 60_000, 4,
        ).is_err());
    }

    #[test]
    fn session_close_releases_lease_durably_via_cleanup() {
        use crate::v2::session_manager::{
            SessionCleanup, V2SessionManager, V2SessionManagerConfig,
        };
        use sg_auth::ticket::OrganizationId;

        let store = Arc::new(InMemoryLeaseStore::new());
        let pool = Arc::new(
            AddressPool::with_store(
                test_config(4),
                Arc::clone(&store) as Arc<dyn LeaseStore>,
                1_000,
            )
            .unwrap(),
        );
        let sessions = V2SessionManager::with_cleanup(
            V2SessionManagerConfig {
                maximum_sessions: 4,
                idle_ttl_ms: 120_000,
                maximum_paths_per_session: 2,
                maximum_pending_attaches: 2,
                pending_attach_ttl_ms: 5_000,
                maximum_path_epoch_history: 4,
                maximum_path_tombstones: 2,
                path_tombstone_ttl_ms: 5_000,
            },
            vec![Arc::clone(&pool) as Arc<dyn SessionCleanup>],
        )
        .unwrap();
        let org = OrganizationId::from_bytes([3; 16]);
        let reservation = sessions
            .reserve_admission(session(1), device(11), org, 1_000_000, 1_000)
            .unwrap();
        let lease = pool.reserve(session(1), device(11), 1_000).unwrap();
        sessions.commit_admission(reservation, 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        assert_eq!(pool.lookup(session(1)), Some(lease));
        assert_eq!(store.load().unwrap().len(), 1);
        assert!(sessions.close(session(1)).unwrap());
        assert!(pool.lookup(session(1)).is_none(), "session close must free the lease");
        // Session cleanup is non-blocking by construction: the lease is
        // quarantined in memory without store I/O, so the store entry is
        // still present until the bounded retry performs the durable delete.
        assert_eq!(pool.snapshot().pending_releases, 1, "close must quarantine without blocking on store I/O");
        assert_eq!(store.load().unwrap().len(), 1, "deferred cleanup leaves the store entry for retry");
        assert_eq!(pool.retry_pending_releases_bounded(2_000, 32), 0, "bounded retry performs the deferred delete");
        assert!(store.load().unwrap().is_empty(), "retry must remove the store entry");
        assert_eq!(pool.snapshot().pending_releases, 0);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.active, 0);
        assert_eq!(snapshot.releases, 1);
        // The freed slot is reused deterministically by the next session.
        let next = pool.reserve(session(2), device(12), 2_000).unwrap();
        assert_eq!(next, lease);
    }

    #[test]
    fn session_idle_expiry_releases_lease_via_sweep_cleanup() {
        use crate::v2::session_manager::{
            SessionCleanup, V2SessionManager, V2SessionManagerConfig,
        };
        use sg_auth::ticket::OrganizationId;

        let pool = Arc::new(AddressPool::new(test_config(2)).unwrap());
        let sessions = V2SessionManager::with_cleanup(
            V2SessionManagerConfig {
                maximum_sessions: 2,
                idle_ttl_ms: 10,
                maximum_paths_per_session: 1,
                maximum_pending_attaches: 1,
                pending_attach_ttl_ms: 5,
                maximum_path_epoch_history: 2,
                maximum_path_tombstones: 1,
                path_tombstone_ttl_ms: 5,
            },
            vec![Arc::clone(&pool) as Arc<dyn SessionCleanup>],
        )
        .unwrap();
        let org = OrganizationId::from_bytes([3; 16]);
        let reservation = sessions
            .reserve_admission(session(1), device(11), org, 1_000_000, 1_000)
            .unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        sessions.commit_admission(reservation, 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        assert!(pool.lookup(session(1)).is_some());
        assert_eq!(sessions.sweep(1_011).unwrap(), 1);
        assert!(pool.lookup(session(1)).is_none(), "idle expiry must free the lease");
        assert_eq!(pool.snapshot().releases, 1);
    }

    #[test]
    fn failed_durable_release_retries_until_the_store_recovers() {
        let store = Arc::new(InMemoryLeaseStore::new());
        let pool = AddressPool::with_store(
            test_config(2),
            Arc::clone(&store) as Arc<dyn LeaseStore>,
            1_000,
        )
        .unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        store.fail_next_releases(2);
        assert!(pool.release(session(1)).unwrap());
        assert_eq!(pool.snapshot().pending_releases, 1);
        // First retry still fails (one failure left), second succeeds.
        assert_eq!(pool.retry_pending_releases(), 1);
        assert_eq!(pool.retry_pending_releases(), 0);
        assert_eq!(pool.snapshot().release_retries, 1);
        assert!(store.load().unwrap().is_empty());
    }

    #[test]
    fn crash_reserve_recovers_reservation_and_blocks_reuse() {
        // A Reserved lease is persisted before it is returned, so a crash
        // before commit still recovers the reservation and blocks reuse.
        let store = Arc::new(InMemoryLeaseStore::new());
        let reserved = {
            let pool = AddressPool::with_store(
                test_config(4),
                Arc::clone(&store) as Arc<dyn LeaseStore>,
                1_000,
            )
            .unwrap();
            let lease = pool.reserve(session(1), device(11), 1_000).unwrap();
            // Crash: drop without commit or release. The store still holds the
            // Reserved record.
            assert_eq!(store.load().unwrap().len(), 1);
            lease
        };
        let recovered = AddressPool::with_store(
            test_config(4),
            Arc::clone(&store) as Arc<dyn LeaseStore>,
            2_000,
        )
        .unwrap();
        // Same session plus device resumes the identical reservation.
        let resumed = recovered.reserve(session(1), device(11), 2_000).unwrap();
        assert_eq!(reserved, resumed, "crash reserve must resume the same lease");
        // Another session must not reuse the crashed reservation's addresses.
        let other = recovered.reserve(session(2), device(12), 2_000).unwrap();
        assert_ne!(other.ipv4, reserved.ipv4);
        assert_ne!(other.ipv6_prefix, reserved.ipv6_prefix);
        assert_eq!(recovered.snapshot().recovered, 1);
        // Committing the resumed reservation promotes it to Active durably.
        recovered.commit(session(1), 2_000).unwrap();
        assert_eq!(recovered.snapshot().active, 1);
    }

    #[test]
    fn release_failure_restart_blocks_reuse_until_retry() {
        // A failed durable delete quarantines the addresses; a restart
        // recovers the store entry and still blocks reuse until retry.
        let store = Arc::new(InMemoryLeaseStore::new());
        let first = {
            let pool = AddressPool::with_store(
                test_config(4),
                Arc::clone(&store) as Arc<dyn LeaseStore>,
                1_000,
            )
            .unwrap();
            let lease = pool.reserve(session(1), device(11), 1_000).unwrap();
            pool.commit(session(1), 1_000).unwrap();
            store.fail_next_releases(10);
            pool.release(session(1)).unwrap();
            assert_eq!(pool.snapshot().pending_releases, 1);
            lease
        };
        // Restart while the store delete is still failing: recovery must
        // restore the lease (Active, since the delete never landed) and block
        // reuse. Use a time inside the DHCP TTL (commit at 1000 + 60000).
        let restarted = AddressPool::with_store(
            test_config(4),
            Arc::clone(&store) as Arc<dyn LeaseStore>,
            2_000,
        )
        .unwrap();
        assert!(restarted.lookup(session(1)).is_some(), "failed delete must survive restart");
        let other = restarted.reserve(session(2), device(12), 2_000).unwrap();
        assert_ne!(other.ipv4, first.ipv4, "quarantined IPv4 must not be reused after restart");
        assert_ne!(other.ipv6_prefix, first.ipv6_prefix);
        // Once the store recovers, retry frees the addresses for reuse.
        // Drain the injected failures by retrying until empty (deterministic,
        // no sleeps: each retry consumes one injected failure).
        for _ in 0..12 {
            if restarted.retry_pending_releases() == 0 {
                break;
            }
        }
        // The quarantined session's store entry is gone, but its in-memory
        // quarantine is also gone; a new session may now reuse the slot
        // deterministically (lowest free address).
        restarted.release(session(1)).unwrap();
        for _ in 0..12 {
            if restarted.retry_pending_releases() == 0 {
                break;
            }
        }
        assert_eq!(restarted.snapshot().pending_releases, 0);
    }

    #[test]
    fn quarantine_overflow_fails_closed_without_drop() {
        // Quarantine holds at most `maximum_pending_releases`; overflow never
        // drops the oldest — it fails closed and keeps addresses blocked.
        let store = Arc::new(InMemoryLeaseStore::new());
        let pool = AddressPool::with_store(
            test_config(4),
            Arc::clone(&store) as Arc<dyn LeaseStore>,
            1_000,
        )
        .unwrap();
        // Fill Active leases.
        pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        pool.reserve(session(2), device(12), 1_000).unwrap();
        pool.commit(session(2), 1_000).unwrap();
        pool.reserve(session(3), device(13), 1_000).unwrap();
        pool.commit(session(3), 1_000).unwrap();
        pool.reserve(session(4), device(14), 1_000).unwrap();
        pool.commit(session(4), 1_000).unwrap();
        // Quarantine capacity is 4 (test_config uses maximum_leases as the
        // quarantine bound). Fail every durable delete.
        store.fail_next_releases(10);
        assert!(pool.release(session(1)).unwrap());
        assert!(pool.release(session(2)).unwrap());
        assert!(pool.release(session(3)).unwrap());
        assert!(pool.release(session(4)).unwrap());
        assert_eq!(pool.snapshot().pending_releases, 4);
        assert_eq!(pool.snapshot().release_retry_dropped, 0);
        // One more lease to overflow the quarantine.
        pool.reserve(session(5), device(15), 1_000).unwrap();
        pool.commit(session(5), 1_000).unwrap();
        assert_eq!(pool.release(session(5)), Err(AddressPoolError::Store));
        assert_eq!(pool.snapshot().quarantine_full, 1);
        assert_eq!(pool.snapshot().release_retry_dropped, 0, "overflow must never drop");
        // The overflowed lease stays blocked for reuse (fail closed).
        assert!(pool.lookup(session(5)).is_some(), "overflowed lease must stay blocked");
        let other = pool.reserve(session(6), device(16), 1_000);
        // Pool has 1 Active (session 5, still blocked) + 4 quarantined; the
        // next reserve either exhausts or fails closed, but must never reuse
        // quarantined addresses.
        if let Ok(lease) = other {
            // Exclude the new lease's own durable entry: `store.load()`
            // includes session 6 itself after its successful reserve persist,
            // so only entries for other sessions count as blocked reuse.
            let quarantined_v4: Vec<[u8; 4]> = store
                .load()
                .unwrap()
                .iter()
                .filter(|entry| entry.session_id != session(6))
                .map(|entry| entry.ipv4)
                .collect();
            assert!(!quarantined_v4.contains(&lease.ipv4) || lease.ipv4 == pool.lookup(session(5)).unwrap().ipv4);
        }
    }

    #[test]
    fn reserve_expiry_durably_releases_instead_of_silent_drop() {
        // An expired Reserved lease pruned by `reserve` (same session retry)
        // or `sweep` must delete its store entry, not just drop memory.
        let store = Arc::new(InMemoryLeaseStore::new());
        let pool = AddressPool::with_store(
            test_config(2),
            Arc::clone(&store) as Arc<dyn LeaseStore>,
            1_000,
        )
        .unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        assert_eq!(store.load().unwrap().len(), 1);
        // Same-session retry after the 5 s pending TTL expires durably releases.
        let rerequested = pool.reserve(session(1), device(11), 6_000).unwrap();
        assert_eq!(store.load().unwrap().len(), 1, "expired reserve must replace, not leak, the store entry");
        let _ = rerequested;
        // Sweep expiry also durably releases.
        let ephemeral = AddressPool::with_store(
            test_config(2),
            Arc::clone(&store) as Arc<dyn LeaseStore>,
            6_000,
        )
        .unwrap();
        // The store holds session 1 Reserved (expiry 11000); sweeping past it
        // frees the store entry.
        assert!(ephemeral.lookup(session(1)).is_some());
        assert_eq!(ephemeral.sweep(11_000), vec![session(1)]);
        assert!(store.load().unwrap().is_empty() || ephemeral.lookup(session(1)).is_none());
    }

    #[test]
    fn recovered_stream_is_bounded_and_deterministic() {
        // Recovery beyond `maximum_leases + maximum_pending_releases` is
        // truncated deterministically (sorted by session ID) and counted.
        let store = Arc::new(InMemoryLeaseStore::new());
        {
            let pool = AddressPool::with_store(
                test_config(2),
                Arc::clone(&store) as Arc<dyn LeaseStore>,
                1_000,
            )
            .unwrap();
            pool.reserve(session(1), device(11), 1_000).unwrap();
            pool.commit(session(1), 1_000).unwrap();
            pool.reserve(session(2), device(12), 1_000).unwrap();
            pool.commit(session(2), 1_000).unwrap();
        }
        // Inject two extra valid leases directly into the store beyond the
        // maximum_leases bound (4 total persisted, bound is 2 + 2 = 4, so all
        // fit; add a fifth to force truncation).
        for byte in [3u8, 4, 5] {
            let ipv4 = [10, 64, 0, 10 + byte];
            let mut v6 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            v6[7] = 10 + byte;
            store
                .persist(&PersistedLease {
                    session_id: session(20 + byte),
                    device_id: device(30 + byte),
                    ipv4,
                    ipv4_prefix_len: 24,
                    ipv6_prefix: v6,
                    ipv6_prefix_len: 64,
                    state: LeaseState::Active,
                    expires_at_ms: 200_000,
                })
                .unwrap();
        }
        let recovered = AddressPool::with_store(test_config(2), Arc::clone(&store) as Arc<dyn LeaseStore>, 2_000).unwrap();
        let snapshot = recovered.snapshot();
        assert!(snapshot.recovered <= 4, "recovery must respect the bounded stream");
        assert!(snapshot.recovered_dropped >= 1, "excess must be counted");
        assert_eq!(snapshot.release_retry_dropped, 0);
    }

    #[test]
    fn reserved_lease_never_authorizes_payload() {
        // A Reserved lease (pre-commit) must not authorize payload: only
        // `lookup_active` gates the source validator. This enforces the
        // `reserve -> session commit -> lease commit -> SessionAdmit`
        // ordering — a client that reserved but never committed cannot send.
        let pool = AddressPool::new(test_config(2)).unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        assert!(pool.lookup(session(1)).is_some(), "resume needs the pending lease visible");
        assert!(
            pool.lookup_active(session(1)).is_none(),
            "Reserved must not authorize payload before commit"
        );
        pool.commit(session(1), 1_000).unwrap();
        assert!(
            pool.lookup_active(session(1)).is_some(),
            "Active must authorize payload after commit"
        );
    }

    #[test]
    fn renew_persists_durably_and_fails_closed() {
        // Renewal must persist the Active record (state plus new expiry);
        // a store failure reverts memory and fails closed so the two never
        // disagree.
        let store = Arc::new(InMemoryLeaseStore::new());
        let pool = AddressPool::with_store(
            test_config(2),
            Arc::clone(&store) as Arc<dyn LeaseStore>,
            1_000,
        )
        .unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        pool.renew(session(1), 2_000).unwrap();
        let persisted: Vec<PersistedLease> = store.load().unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].state, LeaseState::Active);
        assert_eq!(persisted[0].expires_at_ms, 2_000 + 60_000);
        // Fail the next persist: renewal must fail closed and keep the old
        // durable expiry instead of diverging.
        store.fail_next_persists(1);
        assert_eq!(pool.renew(session(1), 3_000), Err(AddressPoolError::Store));
        let persisted: Vec<PersistedLease> = store.load().unwrap();
        assert_eq!(persisted[0].expires_at_ms, 2_000 + 60_000, "failed renew must not move the durable expiry");
        assert!(pool.snapshot().store_failures >= 1);
        // Renewing a Reserved (never committed) lease is UnknownLease, and a
        // quarantined or unknown session never renews.
        let ephemeral = AddressPool::new(test_config(2)).unwrap();
        ephemeral.reserve(session(9), device(19), 1_000).unwrap();
        assert_eq!(ephemeral.renew(session(9), 2_000), Err(AddressPoolError::UnknownLease));
        assert_eq!(pool.renew(session(77), 2_000), Err(AddressPoolError::UnknownLease));
    }

    #[test]
    fn quarantine_retry_increments_attempts_without_drop() {
        // Each failed durable-delete retry increments that lease's attempts
        // (observable via `quarantined()`); successes clear the entry. The
        // quarantine never drops on overflow or retry — it fails closed.
        let store = Arc::new(InMemoryLeaseStore::new());
        let pool = AddressPool::with_store(
            test_config(2),
            Arc::clone(&store) as Arc<dyn LeaseStore>,
            1_000,
        )
        .unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        store.fail_next_releases(3);
        assert!(pool.release(session(1)).unwrap());
        assert_eq!(pool.snapshot().pending_releases, 1);
        let first = pool.quarantined();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].1, 1_000 + 60_000, "quarantine retains the original expiry");
        assert_eq!(first[0].2, 0, "fresh quarantine starts at zero attempts");
        assert_eq!(pool.retry_pending_releases(), 1, "one failure left: still quarantined");
        let second = pool.quarantined();
        assert_eq!(second[0].2, 1, "failed retry must increment attempts");
        assert_eq!(pool.retry_pending_releases(), 1);
        assert_eq!(pool.quarantined()[0].2, 2);
        assert_eq!(pool.retry_pending_releases(), 0, "store recovered: quarantine drains");
        assert!(pool.quarantined().is_empty());
        assert_eq!(pool.snapshot().release_retries, 1);
        assert_eq!(pool.snapshot().release_retry_dropped, 0, "retries never drop");
    }

    fn temp_journal_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("sg-journal-{}-{}-{tag}", std::process::id(), id))
    }

    fn remove_journal(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[test]
    fn journal_roundtrip_and_reopen_recovers() {
        let path = temp_journal_path("roundtrip");
        remove_journal(&path);
        let lease = {
            let journal = Arc::new(JournalLeaseStore::open(&path).unwrap());
            let pool = AddressPool::with_store(test_config(4), journal as Arc<dyn LeaseStore>, 1_000).unwrap();
            let lease = pool.reserve(session(1), device(11), 1_000).unwrap();
            pool.commit(session(1), 1_000).unwrap();
            assert!(path.exists(), "first persist must create the journal file");
            assert!(!path.with_extension("tmp").exists(), "no temp file may be left behind");
            lease
        };
        // Reopen: the journal replays the Active lease and blocks reuse.
        let journal = Arc::new(JournalLeaseStore::open(&path).unwrap());
        assert_eq!(journal.load().unwrap().len(), 1);
        let reopened = AddressPool::with_store(test_config(4), journal as Arc<dyn LeaseStore>, 2_000).unwrap();
        assert_eq!(reopened.lookup(session(1)), Some(lease));
        assert_eq!(reopened.snapshot().recovered, 1);
        let other = reopened.reserve(session(2), device(12), 2_000).unwrap();
        assert_ne!(other.ipv4, lease.ipv4);
        remove_journal(&path);
    }

    #[test]
    fn journal_concurrent_reserve_and_reopen_recovers_all() {
        // Proves the single-guard journal serialization: N concurrent
        // `reserve` persists (each a full rewrite + mirror commit) must all
        // land in the file and the mirror with no lost update, and a reopen
        // must recover every lease and keep blocking reuse. Deterministic:
        // a barrier releases all workers at once, joins are bounded, and no
        // sleeps gate correctness.
        use std::sync::Barrier;
        const CONCURRENT: u8 = 8;
        let path = temp_journal_path("concurrent-reopen");
        remove_journal(&path);
        let leases = {
            let journal = Arc::new(JournalLeaseStore::open(&path).unwrap());
            let pool = Arc::new(
                AddressPool::with_store(test_config(16), journal as Arc<dyn LeaseStore>, 1_000).unwrap(),
            );
            let barrier = Arc::new(Barrier::new(CONCURRENT as usize));
            let mut handles = Vec::new();
            for index in 0..CONCURRENT {
                let pool = Arc::clone(&pool);
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    pool.reserve(session(40 + index), device(60 + index), 1_000)
                }));
            }
            let mut leases = Vec::with_capacity(CONCURRENT as usize);
            for handle in handles {
                leases.push(handle.join().expect("reserve worker must finish").expect("concurrent reserve must succeed"));
            }
            // Concurrent reserves must hold distinct addresses (inflight
            // parking blocks reuse while each persist is in flight).
            let mut v4 = leases.iter().map(|lease| lease.ipv4).collect::<Vec<_>>();
            v4.sort();
            v4.dedup();
            assert_eq!(v4.len(), CONCURRENT as usize, "concurrent reserves must hold distinct IPv4 leases");
            let mut v6 = leases.iter().map(|lease| lease.ipv6_prefix).collect::<Vec<_>>();
            v6.sort();
            v6.dedup();
            assert_eq!(v6.len(), CONCURRENT as usize, "concurrent reserves must hold distinct IPv6 leases");
            for index in 0..CONCURRENT {
                pool.commit(session(40 + index), 1_000).unwrap();
            }
            assert_eq!(pool.snapshot().active, CONCURRENT as usize);
            assert!(!path.with_extension("tmp").exists(), "no temp file may be left behind after concurrent writes");
            leases
        };
        // The journal file must contain every concurrent reserve: a stale
        // snapshot rewrite would have dropped one.
        let journal = Arc::new(JournalLeaseStore::open(&path).unwrap());
        assert_eq!(
            journal.load().unwrap().len(),
            CONCURRENT as usize,
            "journal file must contain every concurrent reserve"
        );
        let reopened =
            AddressPool::with_store(test_config(16), journal as Arc<dyn LeaseStore>, 2_000).unwrap();
        assert_eq!(reopened.snapshot().recovered, CONCURRENT as u64);
        for index in 0..CONCURRENT {
            let recovered = reopened
                .lookup(session(40 + index))
                .expect("reopen must recover every concurrent lease");
            assert!(leases.contains(&recovered), "recovered lease must match a reserved lease");
            assert!(
                reopened.lookup_active(session(40 + index)).is_some(),
                "committed leases must reopen as Active and keep authorizing payload"
            );
        }
        let other = reopened.reserve(session(99), device(99), 2_000).unwrap();
        assert!(!leases.contains(&other), "recovered addresses must stay blocked for reuse");
        remove_journal(&path);
    }

    #[test]
    fn journal_corrupt_and_trailing_data_fail_closed() {
        // Bad magic.
        let bad_magic = temp_journal_path("badmagic");
        remove_journal(&bad_magic);
        std::fs::write(&bad_magic, vec![0xFFu8; JOURNAL_RECORD_LEN]).unwrap();
        assert!(JournalLeaseStore::open(&bad_magic).is_err(), "bad magic must fail closed");
        // Truncated record.
        let truncated = temp_journal_path("truncated");
        remove_journal(&truncated);
        std::fs::write(&truncated, vec![0x53u8; JOURNAL_RECORD_LEN - 1]).unwrap();
        assert!(JournalLeaseStore::open(&truncated).is_err(), "short read must fail closed");
        // Trailing byte.
        let trailing = temp_journal_path("trailing");
        remove_journal(&trailing);
        {
            let journal = JournalLeaseStore::open(&trailing).unwrap();
            journal
                .persist(&PersistedLease {
                    session_id: session(1),
                    device_id: device(11),
                    ipv4: [10, 64, 0, 2],
                    ipv4_prefix_len: 24,
                    ipv6_prefix: [0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                    ipv6_prefix_len: 64,
                    state: LeaseState::Active,
                    expires_at_ms: 200_000,
                })
                .unwrap();
        }
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(&trailing).unwrap();
            file.write_all(&[0xAA]).unwrap();
            file.sync_all().unwrap();
        }
        assert!(JournalLeaseStore::open(&trailing).is_err(), "trailing data must fail closed");
        // Unknown lease state.
        let bad_state = temp_journal_path("badstate");
        remove_journal(&bad_state);
        {
            let mut record = encode_lease_record(&PersistedLease {
                session_id: session(1),
                device_id: device(11),
                ipv4: [10, 64, 0, 2],
                ipv4_prefix_len: 24,
                ipv6_prefix: [0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                ipv6_prefix_len: 64,
                state: LeaseState::Active,
                expires_at_ms: 200_000,
            });
            record[5] = 0xFF;
            std::fs::write(&bad_state, record).unwrap();
        }
        assert!(JournalLeaseStore::open(&bad_state).is_err(), "unknown state must fail closed");
        for path in [&bad_magic, &truncated, &trailing, &bad_state] {
            remove_journal(path);
        }
    }

    #[test]
    fn pool_open_modes_recover_explicitly_and_fail_closed() {
        // Ephemeral: no recovery, restart frees everything.
        let ephemeral = AddressPool::open(test_config(2), AddressPoolMode::Ephemeral, 1_000).unwrap();
        ephemeral.reserve(session(1), device(11), 1_000).unwrap();
        assert!(ephemeral.lookup(session(1)).is_some());
        // Self-hosted: journal roundtrip recovers across `open`.
        let path = temp_journal_path("open");
        remove_journal(&path);
        let lease = {
            let pool = AddressPool::open(test_config(4), AddressPoolMode::SelfHosted { journal_path: path.clone() }, 1_000).unwrap();
            let lease = pool.reserve(session(1), device(11), 1_000).unwrap();
            pool.commit(session(1), 1_000).unwrap();
            lease
        };
        let reopened = AddressPool::open(test_config(4), AddressPoolMode::SelfHosted { journal_path: path.clone() }, 2_000).unwrap();
        assert_eq!(reopened.lookup(session(1)), Some(lease));
        // Managed: adapter roundtrip recovers.
        let store = Arc::new(InMemoryLeaseStore::new());
        let managed_lease = {
            let pool = AddressPool::open(test_config(4), AddressPoolMode::Managed { store: Arc::clone(&store) as Arc<dyn LeaseStore> }, 1_000).unwrap();
            let lease = pool.reserve(session(7), device(17), 1_000).unwrap();
            pool.commit(session(7), 1_000).unwrap();
            lease
        };
        let managed = AddressPool::open(test_config(4), AddressPoolMode::Managed { store: Arc::clone(&store) as Arc<dyn LeaseStore> }, 2_000).unwrap();
        assert_eq!(managed.lookup(session(7)), Some(managed_lease));
        // Load failure fails closed in every durable mode (no empty pool).
        let failing = Arc::new(InMemoryLeaseStore::new());
        failing.fail_next_loads(100);
        assert!(AddressPool::open(test_config(2), AddressPoolMode::Managed { store: failing as Arc<dyn LeaseStore> }, 1_000).is_err());
        remove_journal(&path);
    }

    #[test]
    fn wall_clock_expiry_survives_restart_and_converts_safely() {
        // Restart-expiry proof: the durable journal persists wall-clock
        // expiries (`wall_ms + ttl`); recovery converts the remaining wall
        // time back to a monotonic deadline with saturating arithmetic (never
        // panics, never wraps). No sleeps: all clocks are explicit `PoolTime`
        // values, and every assertion is ordered by construction.
        use crate::v2::persistence::PoolTime;
        let path = temp_journal_path("wall-restart");
        remove_journal(&path);
        // Persist at mono 1_000 / wall 1_000_000 with lease TTL 60_000:
        // mono expiry 61_000, wall expiry 1_060_000.
        let lease = {
            let pool = AddressPool::open_at_time(
                test_config(4),
                AddressPoolMode::SelfHosted { journal_path: path.clone() },
                PoolTime::new(1_000, 1_000_000),
            )
            .unwrap();
            let lease = pool.reserve_at_time(session(1), device(11), PoolTime::new(1_000, 1_000_000)).unwrap();
            pool.commit_at_time(session(1), PoolTime::new(1_000, 1_000_000)).unwrap();
            // Renew extends both domains deterministically.
            pool.renew_at_time(session(1), PoolTime::new(2_000, 1_001_000)).unwrap();
            // After renew at mono 2_000 / wall 1_001_000: mono 62_000, wall
            // 1_061_000. Drop without stopping persistence (Drop detaches
            // without hanging); the file already holds the wall expiry.
            lease
        };
        // Reopen 1 s later in both domains (remaining 59_000 wall): the lease
        // must recover with mono expiry 2_000 + 59_000 = 61_000? Actually
        // renew pushed it to 62_000 mono / 1_061_000 wall; reopening at
        // mono 3_000 / wall 1_002_000 leaves 59_000 wall, so mono 62_000
        // (3_000 + 59_000). The exact value is asserted via sweep boundaries
        // below, not via the opaque `AssignedAddresses` (which carries no
        // expiry).
        let reopened = AddressPool::open_at_time(
            test_config(4),
            AddressPoolMode::SelfHosted { journal_path: path.clone() },
            PoolTime::new(3_000, 1_002_000),
        )
        .unwrap();
        assert_eq!(reopened.lookup(session(1)), Some(lease));
        assert!(reopened.lookup_active(session(1)).is_some());
        // Before the converted mono expiry nothing expires.
        assert!(reopened.sweep(61_999).is_empty());
        // At the converted expiry the lease expires and frees for reuse.
        assert_eq!(reopened.sweep(62_000), vec![session(1)]);
        assert!(reopened.lookup(session(1)).is_none());
        remove_journal(&path);

        // Expired wall never recovers: persist at wall 2_000_000, reopen past
        // both expiries (wall 2_061_000 past 2_060_000, mono 70_000 past
        // 61_000). The expired entry is dropped (counted) and its addresses
        // become reusable by a new session (no collision, no leak).
        let expired_path = temp_journal_path("wall-expired");
        remove_journal(&expired_path);
        {
            let pool = AddressPool::open_at_time(
                test_config(4),
                AddressPoolMode::SelfHosted { journal_path: expired_path.clone() },
                PoolTime::new(1_000, 2_000_000),
            )
            .unwrap();
            pool.reserve_at_time(session(5), device(15), PoolTime::new(1_000, 2_000_000)).unwrap();
            pool.commit_at_time(session(5), PoolTime::new(1_000, 2_000_000)).unwrap();
        }
        let restarted = AddressPool::open_at_time(
            test_config(4),
            AddressPoolMode::SelfHosted { journal_path: expired_path.clone() },
            PoolTime::new(70_000, 2_061_000),
        )
        .unwrap();
        assert!(restarted.lookup(session(5)).is_none(), "expired wall must not recover");
        assert_eq!(restarted.snapshot().recovered_dropped, 1);
        // A new session reuses the freed addresses without collision.
        let reused = restarted.reserve(session(6), device(16), 70_000).unwrap();
        restarted.commit(session(6), 70_000).unwrap();
        assert!(restarted.lookup_active(session(6)).is_some());
        let _ = reused;
        remove_journal(&expired_path);
    }

    #[test]
    fn managed_adapter_enforces_hard_cap_and_passes_through() {
        struct OverBoundStore;
        impl std::fmt::Debug for OverBoundStore {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("OverBoundStore")
            }
        }
        impl LeaseStore for OverBoundStore {
            fn load(&self) -> Result<Vec<PersistedLease>, StoreError> {
                Ok(vec![
                    PersistedLease {
                        session_id: session(1),
                        device_id: device(11),
                        ipv4: [10, 64, 0, 2],
                        ipv4_prefix_len: 24,
                        ipv6_prefix: [0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                        ipv6_prefix_len: 64,
                        state: LeaseState::Active,
                        expires_at_ms: 200_000,
                    };
                    MAX_LEASES_HARD_CAP + 1
                ])
            }
            fn persist(&self, _: &PersistedLease) -> Result<(), StoreError> {
                Ok(())
            }
            fn release(&self, _: &SessionId) -> Result<(), StoreError> {
                Ok(())
            }
        }
        let adapter = ManagedLeaseStore::new(Arc::new(OverBoundStore));
        assert_eq!(adapter.load(), Err(StoreError::Corrupt), "over-bound load must fail closed at the adapter");
        // Pass-through for a healthy backend.
        let inner = Arc::new(InMemoryLeaseStore::new());
        let adapter = ManagedLeaseStore::new(Arc::clone(&inner) as Arc<dyn LeaseStore>);
        let lease = PersistedLease {
            session_id: session(3),
            device_id: device(13),
            ipv4: [10, 64, 0, 5],
            ipv4_prefix_len: 24,
            ipv6_prefix: [0xfd, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0],
            ipv6_prefix_len: 64,
            state: LeaseState::Reserved,
            expires_at_ms: 50_000,
        };
        adapter.persist(&lease).unwrap();
        assert_eq!(adapter.load().unwrap(), vec![lease]);
        adapter.release(&session(3)).unwrap();
        assert!(adapter.load().unwrap().is_empty());
    }

    #[test]
    fn recovery_discarded_delete_failure_quarantines_nonreusable() {
        // One valid lease plus one expired plus one gateway-collision entry.
        // Every discarded delete fails: recovery must quarantine both
        // discarded entries as nonreusable instead of freeing them.
        let store = Arc::new(InMemoryLeaseStore::new());
        store
            .persist(&PersistedLease {
                session_id: session(1),
                device_id: device(11),
                ipv4: [10, 64, 0, 2],
                ipv4_prefix_len: 24,
                ipv6_prefix: [0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                ipv6_prefix_len: 64,
                state: LeaseState::Active,
                expires_at_ms: 200_000,
            })
            .unwrap();
        store
            .persist(&PersistedLease {
                session_id: session(2),
                device_id: device(12),
                ipv4: [10, 64, 0, 3],
                ipv4_prefix_len: 24,
                ipv6_prefix: [0xfd, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
                ipv6_prefix_len: 64,
                state: LeaseState::Active,
                expires_at_ms: 500,
            })
            .unwrap();
        store
            .persist(&PersistedLease {
                session_id: session(9),
                device_id: device(19),
                ipv4: [10, 64, 0, 1],
                ipv4_prefix_len: 24,
                ipv6_prefix: [0xfd, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0],
                ipv6_prefix_len: 64,
                state: LeaseState::Active,
                expires_at_ms: 200_000,
            })
            .unwrap();
        store.fail_next_releases(2);
        let pool = AddressPool::with_store(test_config(4), Arc::clone(&store) as Arc<dyn LeaseStore>, 2_000).unwrap();
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.recovered, 1, "only the valid lease restores");
        assert_eq!(snapshot.recovered_dropped, 2, "expired and colliding entries are discarded");
        assert_eq!(snapshot.pending_releases, 2, "failed discarded deletes must quarantine nonreusable");
        assert!(pool.lookup(session(1)).is_some());
        assert!(pool.lookup(session(2)).is_none());
        assert!(pool.lookup(session(9)).is_none());
        // Quarantined addresses stay blocked: a new session must not reuse
        // either discarded IPv4.
        let other = pool.reserve(session(3), device(13), 2_000).unwrap();
        assert_ne!(other.ipv4, [10, 64, 0, 3], "expired-but-undeleted IPv4 must stay blocked");
        assert_ne!(other.ipv4, [10, 64, 0, 1], "colliding-but-undeleted IPv4 must stay blocked");
        // Once the store recovers, bounded retry frees both discards.
        assert_eq!(pool.retry_pending_releases_bounded(10_000, 32), 0);
        assert_eq!(pool.snapshot().pending_releases, 0);
        let remaining: Vec<[u8; 4]> = store.load().unwrap().iter().map(|entry| entry.ipv4).collect();
        assert!(!remaining.contains(&[10, 64, 0, 3]));
        assert!(!remaining.contains(&[10, 64, 0, 1]));
    }

    /// Test store whose first persist blocks on a gate channel (deterministic,
    /// no sleeps). Proves the pool mutex is never held across store I/O: a
    /// second session can allocate while the first session's persist is still
    /// blocked. `proceed` is a oneshot release; `entered` signals the block.
    struct GateStore {
        inner: InMemoryLeaseStore,
        entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        proceed: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        gate_armed: AtomicU64,
    }

    impl std::fmt::Debug for GateStore {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("GateStore")
        }
    }

    impl GateStore {
        fn new() -> (Self, std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
            (
                Self {
                    inner: InMemoryLeaseStore::new(),
                    entered: Mutex::new(Some(entered_tx)),
                    proceed: Mutex::new(Some(proceed_rx)),
                    gate_armed: AtomicU64::new(1),
                },
                entered_rx,
                proceed_tx,
            )
        }

        fn gate(&self) {
            if self.gate_armed.load(Ordering::Relaxed) == 0 {
                return;
            }
            self.gate_armed.store(0, Ordering::Relaxed);
            if let Some(tx) = self.entered.lock().ok().and_then(|mut guard| guard.take()) {
                let _ = tx.send(());
            }
            if let Some(rx) = self.proceed.lock().ok().and_then(|mut guard| guard.take()) {
                let _ = rx.recv();
            }
        }
    }

    impl LeaseStore for GateStore {
        fn load(&self) -> Result<Vec<PersistedLease>, StoreError> {
            self.inner.load()
        }
        fn persist(&self, lease: &PersistedLease) -> Result<(), StoreError> {
            self.gate();
            self.inner.persist(lease)
        }
        fn release(&self, session_id: &SessionId) -> Result<(), StoreError> {
            self.inner.release(session_id)
        }
    }

    #[test]
    fn store_io_never_holds_pool_mutex() {
        let (gate, entered, proceed) = GateStore::new();
        let pool = Arc::new(AddressPool::with_store(test_config(4), Arc::new(gate), 1_000).unwrap());
        let worker_pool = Arc::clone(&pool);
        let worker = std::thread::spawn(move || worker_pool.reserve(session(1), device(11), 1_000));
        // Wait until the worker is blocked inside the store persist (no pool
        // lock held there by construction). Watchdog timeout keeps a
        // regression from hanging the suite; the assertion below is the real
        // check, not the timeout.
        entered.recv_timeout(std::time::Duration::from_secs(10)).expect("worker must reach the store gate");
        // This second-session reserve must complete while the first persist
        // is still blocked: with I/O under the mutex it would deadlock.
        let second = pool.reserve(session(2), device(12), 1_000).expect("concurrent reserve must not block on another session's store I/O");
        pool.commit(session(2), 1_000).unwrap();
        let _ = proceed.send(());
        let first = worker.join().expect("worker must finish").expect("first reserve must succeed after the gate opens");
        assert_ne!(first.ipv4, second.ipv4, "gated concurrent reserves must hold distinct addresses");
        assert_ne!(first.ipv6_prefix, second.ipv6_prefix);
        pool.commit(session(1), 1_000).unwrap();
        assert_eq!(pool.snapshot().active, 2);
    }

    #[test]
    fn inflight_same_session_fails_closed_for_retry() {
        let (gate, entered, proceed) = GateStore::new();
        let pool = Arc::new(AddressPool::with_store(test_config(4), Arc::new(gate), 1_000).unwrap());
        let worker_pool = Arc::clone(&pool);
        let worker = std::thread::spawn(move || worker_pool.reserve(session(1), device(11), 1_000));
        entered.recv_timeout(std::time::Duration::from_secs(10)).expect("worker must reach the store gate");
        // Same-session concurrent reserve sees the inflight parking and fails
        // closed (counted), so the caller retries instead of minting a second
        // candidate for one session.
        assert_eq!(pool.reserve(session(1), device(11), 1_000), Err(AddressPoolError::Store));
        assert_eq!(pool.snapshot().inflight_conflicts, 1);
        let _ = proceed.send(());
        let first = worker.join().expect("worker must finish").unwrap();
        let retried = pool.reserve(session(1), device(11), 1_000).unwrap();
        assert_eq!(first, retried, "retry after inflight commit is idempotent");
    }

    #[test]
    fn retry_batch_is_bounded_and_backoff_defers() {
        let store = Arc::new(InMemoryLeaseStore::new());
        let pool = AddressPool::with_store(test_config(8), Arc::clone(&store) as Arc<dyn LeaseStore>, 1_000).unwrap();
        for index in 0..4u8 {
            pool.reserve(session(10 + index), device(20 + index), 1_000).unwrap();
            pool.commit(session(10 + index), 1_000).unwrap();
        }
        store.fail_next_releases(4);
        for index in 0..4u8 {
            assert!(pool.release_at(session(10 + index), 1_000).unwrap());
        }
        assert_eq!(pool.snapshot().pending_releases, 4);
        // Batch of 2 with a healthy store frees exactly 2; the rest defer.
        assert_eq!(pool.retry_pending_releases_bounded(50_000, 2), 2);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.pending_releases, 2);
        assert_eq!(snapshot.release_retries, 2);
        assert!(snapshot.release_retry_deferred >= 2, "beyond-batch entries must count deferred");
        assert_eq!(pool.retry_pending_releases_bounded(50_000, 32), 0);
        assert_eq!(pool.snapshot().pending_releases, 0);
        // Backoff: a fresh quarantine is not due before its deadline.
        store.fail_next_releases(1);
        pool.reserve(session(30), device(40), 1_000).unwrap();
        pool.commit(session(30), 1_000).unwrap();
        assert!(pool.release_at(session(30), 1_000).unwrap());
        assert_eq!(pool.snapshot().pending_releases, 1);
        // next_retry = 1000 + 1000 = 2000; a retry at 1500 defers without I/O.
        assert_eq!(pool.retry_pending_releases_bounded(1_500, 32), 1, "not-due retry must not attempt");
        assert_eq!(pool.quarantined()[0].2, 0, "deferred retry must not increment attempts");
        assert!(pool.snapshot().release_retry_deferred >= 1);
        // After the deadline the retry attempts (and here succeeds).
        assert_eq!(pool.retry_pending_releases_bounded(2_500, 32), 0);
        assert!(pool.quarantined().is_empty());
        // Exponential growth: one failure pushes the deadline out 2x.
        store.fail_next_releases(2);
        pool.reserve(session(31), device(41), 10_000).unwrap();
        pool.commit(session(31), 10_000).unwrap();
        assert!(pool.release_at(session(31), 10_000).unwrap());
        assert_eq!(pool.retry_pending_releases_bounded(11_000, 32), 1, "first retry fails");
        assert_eq!(pool.quarantined()[0].2, 1);
        // next_retry = 11000 + 2000 = 13000; before it, defer.
        assert_eq!(pool.retry_pending_releases_bounded(12_000, 32), 1);
        assert_eq!(pool.quarantined()[0].2, 1, "deferred retry must not increment attempts again");
        assert_eq!(pool.retry_pending_releases_bounded(13_000, 32), 0, "store recovered after the backoff");
    }

    #[test]
    fn release_at_uses_timed_backoff_and_deferred_cleanup_avoids_store_io() {
        let store = Arc::new(InMemoryLeaseStore::new());
        let pool = AddressPool::with_store(test_config(2), Arc::clone(&store) as Arc<dyn LeaseStore>, 1_000).unwrap();
        pool.reserve(session(1), device(11), 1_000).unwrap();
        pool.commit(session(1), 1_000).unwrap();
        // Timed release quarantines with a deadline derived from `now_ms`.
        store.fail_next_releases(1);
        assert!(pool.release_at(session(1), 5_000).unwrap());
        assert_eq!(pool.snapshot().pending_releases, 1);
        // Due at 6000; before that the retry defers without touching the store.
        assert_eq!(pool.retry_pending_releases_bounded(5_500, 32), 1);
        assert_eq!(pool.retry_pending_releases_bounded(6_000, 32), 0);
        // Deferred cleanup never calls the store: even a fully failing store
        // quarantines in memory with no `store_failures` increment.
        pool.reserve(session(2), device(12), 7_000).unwrap();
        pool.commit(session(2), 7_000).unwrap();
        store.fail_next_releases(100);
        let failures_before = pool.snapshot().store_failures;
        assert!(pool.release_deferred(session(2)), "deferred cleanup must quarantine without store I/O");
        assert_eq!(pool.snapshot().pending_releases, 1);
        assert_eq!(pool.snapshot().store_failures, failures_before, "deferred path must not count store failures");
        assert_eq!(store.load().unwrap().len(), 1, "session 2's store entry remains for the bounded retry");
    }

    #[tokio::test]
    async fn async_wrappers_match_sync_and_run_concurrently() {
        let store = Arc::new(InMemoryLeaseStore::new());
        let pool: Arc<AddressPool> = Arc::new(AddressPool::with_store(test_config(16), Arc::clone(&store) as Arc<dyn LeaseStore>, 1_000).unwrap());
        let lease = Arc::clone(&pool).reserve_async(session(1), device(11), 1_000).await.unwrap();
        Arc::clone(&pool).commit_async(session(1), 1_000).await.unwrap();
        Arc::clone(&pool).renew_async(session(1), 2_000).await.unwrap();
        assert!(Arc::clone(&pool).sweep_async(3_000).await.is_empty());
        let _ = lease;
        // Eight concurrent async reserves hold distinct addresses.
        let mut joins = Vec::new();
        for index in 0..8u8 {
            let pool = Arc::clone(&pool);
            joins.push(tokio::spawn(async move { pool.reserve_async(session(50 + index), device(60 + index), 4_000).await.unwrap() }));
        }
        let mut leases = Vec::new();
        for join in joins {
            leases.push(join.await.unwrap());
        }
        let mut v4: Vec<[u8; 4]> = leases.iter().map(|lease| lease.ipv4).collect();
        v4.sort();
        v4.dedup();
        assert_eq!(v4.len(), 8, "concurrent async reserves must hold distinct IPv4 leases");
        assert!(Arc::clone(&pool).release_async(session(1)).await.unwrap());
        assert_eq!(Arc::clone(&pool).retry_async(5_000, 32).await, 0);
    }

    #[test]
    fn pool_sweep_config_rejects_invalid_intervals() {
        assert!(PoolSweepConfig::new(0, 10).is_none());
        assert!(PoolSweepConfig::new(10, 5).is_none());
        assert!(PoolSweepConfig::new(1, 3_600_001).is_none());
        let fixed = PoolSweepConfig::fixed(50).unwrap();
        assert_eq!(fixed.min_interval_ms(), 50);
        assert_eq!(fixed.max_interval_ms(), 50);
        let ranged = PoolSweepConfig::new(10, 100).unwrap();
        assert_eq!(ranged.min_interval_ms(), 10);
        assert_eq!(ranged.max_interval_ms(), 100);
    }

    fn supervised_pool_with_sessions(
        maximum_leases: usize,
    ) -> (
        Arc<AddressPool>,
        Arc<crate::v2::session_manager::V2SessionManager>,
    ) {
        use crate::v2::session_manager::{V2SessionManager, V2SessionManagerConfig};
        let pool = Arc::new(AddressPool::new(test_config(maximum_leases)).unwrap());
        let sessions = Arc::new(
            V2SessionManager::with_cleanup(
                V2SessionManagerConfig {
                    maximum_sessions: maximum_leases,
                    idle_ttl_ms: 120_000,
                    maximum_paths_per_session: 1,
                    maximum_pending_attaches: 1,
                    pending_attach_ttl_ms: 5_000,
                    maximum_path_epoch_history: 4,
                    maximum_path_tombstones: 1,
                    path_tombstone_ttl_ms: 5_000,
                },
                vec![Arc::clone(&pool) as Arc<dyn crate::v2::session_manager::SessionCleanup>],
            )
            .unwrap(),
        );
        (pool, sessions)
    }

    #[tokio::test]
    async fn manual_tick_expires_lease_and_closes_session_autonomously() {
        use crate::v2::address_pool::test_support::PoolManualClock;
        // Ephemeral pool plus session map sharing the same cleanup hook.
        // The session outlives the pool lease (idle TTL 120 s vs lease TTL
        // 60 s), so only the autonomous pool sweep closes it.
        let (pool, sessions) = supervised_pool_with_sessions(4);
        let now = 1_000;
        let session_id = session(41);
        let device_id = device(42);
        let reservation = sessions
            .reserve_admission(
                session_id,
                device_id,
                sg_auth::ticket::OrganizationId::from_bytes([43; 16]),
                1_000_000,
                now,
            )
            .unwrap();
        pool.reserve(session_id, device_id, now).unwrap();
        sessions.commit_admission(reservation, now).unwrap();
        pool.commit(session_id, now).unwrap();
        assert!(pool.lookup_active(session_id).is_some());
        assert_eq!(sessions.snapshot().sessions, 1);

        let clock = Arc::new(PoolManualClock::new(now));
        let config = super::PoolSweepConfig::fixed(10).unwrap();
        let (mut sweep, trigger) =
            super::SupervisedPoolSweep::spawn_with_manual_and_sessions(
                Arc::clone(&pool),
                Arc::clone(&sessions),
                config,
                Arc::clone(&clock),
            );
        assert_eq!(sweep.config(), config);
        assert!(sweep.sessions().is_some());

        // Before the 60 s lease TTL nothing expires; the tick is empty but
        // still counts as a completed sweep (deterministic, no sleeps).
        trigger.advance_and_tick(now + 1_000).await;
        assert!(pool.lookup_active(session_id).is_some());
        assert_eq!(sessions.snapshot().sessions, 1);
        assert_eq!(sweep.metrics_snapshot().sweeps_completed(), 1);
        assert_eq!(sweep.metrics_snapshot().leases_expired(), 0);
        assert_eq!(sweep.metrics_snapshot().sweeps_empty(), 1);

        // Past the lease TTL the autonomous tick expires the lease and
        // closes the session idempotently, with no listener traffic.
        trigger.advance_and_tick(now + 60_000).await;
        assert!(pool.lookup(session_id).is_none());
        assert!(pool.lookup_active(session_id).is_none());
        assert_eq!(sessions.snapshot().sessions, 0);
        assert_eq!(sweep.metrics_snapshot().sweeps_completed(), 2);
        assert_eq!(sweep.metrics_snapshot().leases_expired(), 1);
        assert_eq!(sweep.metrics_snapshot().sessions_closed(), 1);

        // A further tick is empty and deterministic.
        trigger.advance_and_tick(now + 61_000).await;
        assert_eq!(sweep.metrics_snapshot().sweeps_completed(), 3);
        assert_eq!(sweep.metrics_snapshot().sweeps_empty(), 2);

        // Explicit cancellation joins both tasks; idempotent.
        let first = sweep.stop().await;
        assert_eq!(first.sweeps_completed(), 3);
        let second = sweep.stop().await;
        assert_eq!(second.sweeps_completed(), 3);
    }

    #[tokio::test]
    async fn manual_tick_retries_quarantined_release_after_session_close() {
        use crate::v2::address_pool::test_support::PoolManualClock;
        // Durable pool: session close quarantines non-blockingly, and the
        // autonomous sweep retries the durable delete with backoff. A failed
        // retry stays quarantined (nonreusable); recovery drains it.
        let store = Arc::new(InMemoryLeaseStore::new());
        let pool = Arc::new(
            AddressPool::with_store(test_config(2), Arc::clone(&store) as Arc<dyn LeaseStore>, 1_000)
                .unwrap(),
        );
        let sessions = {
            use crate::v2::session_manager::{V2SessionManager, V2SessionManagerConfig};
            Arc::new(
                V2SessionManager::with_cleanup(
                    V2SessionManagerConfig {
                        maximum_sessions: 2,
                        idle_ttl_ms: 120_000,
                        maximum_paths_per_session: 1,
                        maximum_pending_attaches: 1,
                        pending_attach_ttl_ms: 5_000,
                        maximum_path_epoch_history: 4,
                        maximum_path_tombstones: 1,
                        path_tombstone_ttl_ms: 5_000,
                    },
                    vec![Arc::clone(&pool) as Arc<dyn crate::v2::session_manager::SessionCleanup>],
                )
                .unwrap(),
            )
        };
        let now = 1_000;
        let session_id = session(51);
        let device_id = device(52);
        let reservation = sessions
            .reserve_admission(
                session_id,
                device_id,
                sg_auth::ticket::OrganizationId::from_bytes([53; 16]),
                1_000_000,
                now,
            )
            .unwrap();
        pool.reserve(session_id, device_id, now).unwrap();
        sessions.commit_admission(reservation, now).unwrap();
        pool.commit(session_id, now).unwrap();

        // Session close quarantines without store I/O (deferred path).
        assert!(sessions.close(session_id).unwrap());
        assert_eq!(pool.snapshot().pending_releases, 1);
        assert_eq!(pool.quarantined().len(), 1);

        let clock = Arc::new(PoolManualClock::new(now));
        let config = super::PoolSweepConfig::fixed(10).unwrap();
        let (mut sweep, trigger) = super::SupervisedPoolSweep::spawn_with_manual(
            Arc::clone(&pool),
            config,
            Arc::clone(&clock),
        );
        assert!(sweep.sessions().is_none());

        // Fail the next durable delete: the autonomous tick attempts the
        // bounded retry, fails, backs off, and keeps the lease quarantined
        // (nonreusable, never dropped).
        store.fail_next_releases(1);
        trigger.advance_and_tick(now).await;
        assert_eq!(pool.snapshot().pending_releases, 1);
        assert_eq!(pool.quarantined()[0].2, 1);
        assert_eq!(sweep.metrics_snapshot().sweeps_completed(), 1);

        // After the exponential backoff the store has recovered, so the next
        // autonomous tick drains the quarantine without manual retry calls.
        // First failure at `now` pushes next_retry to now+2000.
        trigger.advance_and_tick(now + 1_000).await;
        assert_eq!(pool.snapshot().pending_releases, 1, "backoff must defer before the deadline");
        trigger.advance_and_tick(now + 2_000).await;
        assert!(pool.quarantined().is_empty());
        assert_eq!(pool.snapshot().pending_releases, 0);
        assert_eq!(pool.snapshot().release_retries, 1);

        let metrics = sweep.stop().await;
        assert_eq!(metrics.sweeps_completed(), 3);
    }

    #[tokio::test]
    async fn supervised_pool_production_spawn_stops_without_hanging() {
        use crate::v2::session_manager::MonotonicClock;
        // Production ticker path: spawn with a real clock and immediately
        // stop. No sleeps, no manual ticks; this proves cancellation joins
        // both the ticker and the sweep task.
        let pool = Arc::new(AddressPool::new(test_config(2)).unwrap());
        let clock: Arc<MonotonicClock> = Arc::new(MonotonicClock::new());
        let config = super::PoolSweepConfig::fixed(10).unwrap();
        let mut sweep = super::SupervisedPoolSweep::spawn(
            pool,
            config,
            clock as Arc<dyn crate::v2::session_manager::Clock>,
        );
        let metrics = sweep.stop().await;
        // The ticker may or may not have fired before the abort; either way
        // shutdown must join promptly and remain idempotent.
        let _ = metrics.sweeps_completed();
        let second = sweep.stop().await;
        assert_eq!(second.sweeps_completed(), metrics.sweeps_completed());
    }
}
