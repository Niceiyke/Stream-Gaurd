//! Bounded per-flow duplicate suppression with first-valid-wins semantics.
//!
//! [`SessionDedup`] is the low-level primitive underneath deadline reorder:
//! it remembers which packet IDs have already been accepted for each complete
//! [`ReceiveKey`](super::ReceiveKey) (session, direction, key epoch, flow)
//! and drops repeats. The first valid arrival wins whether it arrived as a
//! primary transmission or a redundant copy on another path.
//!
//! Bounds: each flow remembers at most `max_packets_per_flow` IDs; the
//! session holds at most `max_flows` flows. When a flow table is full the
//! smallest (oldest, since IDs are monotonic) entry is evicted and counted;
//! when the session is full the least-recently-active flow is evicted and
//! counted. Per-packet eviction inside a live flow may re-accept an evicted
//! ID here; the reorder layer still guards the delivered prefix with
//! `next_expected` and drops it as stale there.
//!
//! Flow-level removal is replay-safe: evicting or expiring a whole flow
//! installs a bounded per-key tombstone holding the flow's high-watermark
//! (maximum observed packet ID) until `tombstone_ttl_ms`. A replay with an ID
//! at or below the watermark is dropped as a duplicate and can never become a
//! new first arrival. Only an ID strictly beyond the watermark (genuinely new
//! data) resurrects the key and clears the tombstone. Tombstones are bounded
//! by `max_tombstones` with TTL expiry and LRU-by-expiry eviction, so replay
//! protection never grows unbounded state. Inactive flows expire through
//! explicit `expire(now_ms)` using the engine's monotonic millisecond clock.
//!
//! Metrics count packets and flows only. They never contain payloads,
//! addresses, or destination history.

use std::collections::{BTreeSet, HashMap};

use sg_core::v2::PacketId;
use thiserror::Error;

use super::ReceiveKey;

/// Limits for [`SessionDedup`]. All bounds are strict upper bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DedupLimits {
    /// Maximum distinct flows remembered per session.
    pub max_flows: usize,
    /// Maximum packet IDs remembered per flow.
    pub max_packets_per_flow: usize,
    /// Milliseconds after last activity before a flow expires.
    pub flow_idle_ttl_ms: u64,
    /// Maximum per-key tombstones remembered after flow eviction/expiry.
    pub max_tombstones: usize,
    /// Milliseconds a tombstone high-watermark is retained.
    pub tombstone_ttl_ms: u64,
}

impl DedupLimits {
    /// Conservative test-friendly default: 256 flows, 512 IDs each, 30s flow
    /// TTL, 256 tombstones retained for 60s.
    #[must_use]
    pub const fn default_limits() -> Self {
        Self {
            max_flows: 256,
            max_packets_per_flow: 512,
            flow_idle_ttl_ms: 30_000,
            max_tombstones: 256,
            tombstone_ttl_ms: 60_000,
        }
    }

    fn validate(self) -> Result<(), DedupError> {
        if self.max_flows == 0
            || self.max_packets_per_flow == 0
            || self.flow_idle_ttl_ms == 0
            || self.max_tombstones == 0
            || self.tombstone_ttl_ms == 0
        {
            return Err(DedupError::InvalidLimits);
        }
        Ok(())
    }
}

impl Default for DedupLimits {
    fn default() -> Self {
        Self::default_limits()
    }
}

/// Why a dedup table could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DedupError {
    /// A limit was zero.
    #[error("dedup limits must all be nonzero")]
    InvalidLimits,
}

/// Outcome of one [`SessionDedup::observe`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupOutcome {
    /// First time this ID was seen for this key.
    New,
    /// This ID was already accepted; the caller must drop the copy.
    Duplicate,
}

impl DedupOutcome {
    /// True when the packet must be dropped as a repeat.
    #[must_use]
    pub const fn is_duplicate(self) -> bool {
        matches!(self, Self::Duplicate)
    }
}

/// Aggregate dedup outcomes. Counts only; no packet content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DedupMetrics {
    /// Distinct flows currently remembered.
    pub flows: usize,
    /// Tombstones currently remembered (bounded replay guards).
    pub tombstones: usize,
    /// Total `New` observations.
    pub packets_seen: u64,
    /// Total `Duplicate` observations.
    pub duplicates_dropped: u64,
    /// Replays dropped by a tombstone high-watermark (subset of duplicates).
    pub tombstone_hits: u64,
    /// Packet IDs evicted because a flow was full.
    pub packets_evicted_capacity: u64,
    /// Flows evicted because the session was full.
    pub flows_evicted_capacity: u64,
    /// Flows removed by idle TTL.
    pub flows_expired_idle: u64,
    /// Tombstones evicted because the tombstone table was full.
    pub tombstones_evicted_capacity: u64,
    /// Tombstones removed by TTL expiry.
    pub tombstones_expired: u64,
}

#[derive(Debug)]
struct FlowDedup {
    seen: BTreeSet<u64>,
    last_activity_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct DedupTombstone {
    /// Maximum packet ID observed for the evicted/expired key.
    watermark: u64,
    /// Monotonic time when the tombstone expires.
    expires_at_ms: u64,
}

/// Bounded session dedup table keyed by the complete receive key.
pub struct SessionDedup {
    limits: DedupLimits,
    flows: HashMap<ReceiveKey, FlowDedup>,
    tombstones: HashMap<ReceiveKey, DedupTombstone>,
    metrics: DedupMetrics,
}

impl std::fmt::Debug for SessionDedup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally redacted: keys identify sessions/flows and must not
        // appear in logs. Only aggregate counts are observable.
        formatter
            .debug_struct("SessionDedup")
            .field("metrics", &self.metrics())
            .finish()
    }
}

impl SessionDedup {
    /// Creates an empty table.
    pub fn new(limits: DedupLimits) -> Result<Self, DedupError> {
        limits.validate()?;
        Ok(Self {
            limits,
            flows: HashMap::new(),
            tombstones: HashMap::new(),
            metrics: DedupMetrics::default(),
        })
    }

    /// Observes one packet ID for `key` at `now_ms`.
    ///
    /// First-valid-wins: the first observation returns [`DedupOutcome::New`]
    /// and later observations of the same ID return
    /// [`DedupOutcome::Duplicate`]. Any observation (new or duplicate) marks
    /// the flow active, except that a brand-new flow records `now_ms` as its
    /// activity timestamp.
    ///
    /// A live tombstone for an evicted/expired key rejects replays at or
    /// below its high-watermark as duplicates so they can never resurrect the
    /// flow as a first arrival. Only an ID strictly beyond the watermark is
    /// treated as genuinely new data: the tombstone is cleared and a fresh
    /// flow is opened. Expired tombstones are forgotten and no longer block.
    pub fn observe(
        &mut self,
        key: ReceiveKey,
        packet_id: PacketId,
        now_ms: u64,
    ) -> DedupOutcome {
        let id = packet_id.get();
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_activity_ms = now_ms;
            if flow.seen.contains(&id) {
                self.metrics.duplicates_dropped =
                    self.metrics.duplicates_dropped.saturating_add(1);
                return DedupOutcome::Duplicate;
            }
            if flow.seen.len() >= self.limits.max_packets_per_flow {
                // Evict the smallest (oldest under the monotonic contract)
                // so the table stays bounded; the reorder prefix guard keeps
                // this safe and the eviction is counted.
                if let Some(smallest) = flow.seen.iter().next().copied() {
                    flow.seen.remove(&smallest);
                    self.metrics.packets_evicted_capacity =
                        self.metrics.packets_evicted_capacity.saturating_add(1);
                }
            }
            flow.seen.insert(id);
            self.metrics.packets_seen = self.metrics.packets_seen.saturating_add(1);
            return DedupOutcome::New;
        }
        if let Some(tombstone) = self.tombstones.get(&key).copied() {
            if now_ms >= tombstone.expires_at_ms {
                self.tombstones.remove(&key);
                self.metrics.tombstones_expired =
                    self.metrics.tombstones_expired.saturating_add(1);
            } else if id <= tombstone.watermark {
                self.metrics.duplicates_dropped =
                    self.metrics.duplicates_dropped.saturating_add(1);
                self.metrics.tombstone_hits =
                    self.metrics.tombstone_hits.saturating_add(1);
                return DedupOutcome::Duplicate;
            } else {
                // Genuinely new ID beyond the previous maximum: forget the
                // tombstone and open a fresh flow below.
                self.tombstones.remove(&key);
            }
        }
        if self.flows.len() >= self.limits.max_flows {
            self.evict_oldest_flow(now_ms);
        }
        let mut seen = BTreeSet::new();
        seen.insert(id);
        self.flows.insert(
            key,
            FlowDedup {
                seen,
                last_activity_ms: now_ms,
            },
        );
        self.metrics.packets_seen = self.metrics.packets_seen.saturating_add(1);
        self.refresh_counts();
        DedupOutcome::New
    }

    /// Removes flows idle for at least the TTL. Returns expired flow count.
    ///
    /// Each expired flow installs a tombstone high-watermark so immediate
    /// replays are still dropped. Expired tombstones are reaped in the same
    /// call to keep total state bounded.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        self.purge_expired_tombstones(now_ms);
        let ttl = self.limits.flow_idle_ttl_ms;
        let idle: Vec<(ReceiveKey, u64)> = self
            .flows
            .iter()
            .filter(|(_, flow)| now_ms.saturating_sub(flow.last_activity_ms) >= ttl)
            .map(|(key, flow)| (*key, flow.seen.iter().next_back().copied().unwrap_or(0)))
            .collect();
        let expired = idle.len();
        for (key, watermark) in idle {
            self.flows.remove(&key);
            self.insert_tombstone(key, watermark, now_ms);
        }
        self.metrics.flows_expired_idle = self
            .metrics
            .flows_expired_idle
            .saturating_add(expired as u64);
        self.refresh_counts();
        expired
    }

    /// Current aggregate metrics.
    #[must_use]
    pub fn metrics(&self) -> DedupMetrics {
        let mut metrics = self.metrics;
        metrics.flows = self.flows.len();
        metrics.tombstones = self.tombstones.len();
        metrics
    }

    /// Number of flows currently remembered.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Number of tombstones currently remembered.
    #[must_use]
    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }

    fn evict_oldest_flow(&mut self, now_ms: u64) {
        let oldest = self
            .flows
            .iter()
            .min_by_key(|(_, flow)| flow.last_activity_ms)
            .map(|(key, flow)| (*key, flow.seen.iter().next_back().copied().unwrap_or(0)));
        if let Some((key, watermark)) = oldest {
            self.flows.remove(&key);
            self.metrics.flows_evicted_capacity = self
                .metrics
                .flows_evicted_capacity
                .saturating_add(1);
            self.insert_tombstone(key, watermark, now_ms);
        }
        self.refresh_counts();
    }

    fn insert_tombstone(&mut self, key: ReceiveKey, watermark: u64, now_ms: u64) {
        self.purge_expired_tombstones(now_ms);
        if self.tombstones.len() >= self.limits.max_tombstones {
            // Bounded: evict the tombstone expiring soonest (oldest). Ties
            // break on the smaller watermark, then on the deterministic key
            // order, so the victim never depends on HashMap iteration order
            // (which is randomized per map instance).
            let oldest = self
                .tombstones
                .iter()
                .min_by(|a, b| {
                    (a.1.expires_at_ms, a.1.watermark)
                        .cmp(&(b.1.expires_at_ms, b.1.watermark))
                        .then_with(|| a.0.deterministic_cmp(b.0))
                })
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.tombstones.remove(&oldest);
                self.metrics.tombstones_evicted_capacity = self
                    .metrics
                    .tombstones_evicted_capacity
                    .saturating_add(1);
            }
        }
        self.tombstones.insert(
            key,
            DedupTombstone {
                watermark,
                expires_at_ms: now_ms.saturating_add(self.limits.tombstone_ttl_ms),
            },
        );
        self.refresh_counts();
    }

    fn purge_expired_tombstones(&mut self, now_ms: u64) {
        let before = self.tombstones.len();
        self.tombstones.retain(|_, tombstone| now_ms < tombstone.expires_at_ms);
        let reaped = before.saturating_sub(self.tombstones.len());
        self.metrics.tombstones_expired = self
            .metrics
            .tombstones_expired
            .saturating_add(reaped as u64);
        self.refresh_counts();
    }

    fn refresh_counts(&mut self) {
        self.metrics.flows = self.flows.len();
        self.metrics.tombstones = self.tombstones.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sg_core::v2::{DeviceId, FlowId, SessionId};
    use sg_protocol::v2::Direction;

    const SESSION_A: SessionId = SessionId::from_bytes([0xA1; 16]);
    const SESSION_B: SessionId = SessionId::from_bytes([0xB2; 16]);

    fn key(session: SessionId, direction: Direction, key_epoch: u32, flow: u64) -> ReceiveKey {
        ReceiveKey::new(session, direction, key_epoch, FlowId::new(flow))
    }

    #[test]
    fn invalid_limits_are_rejected() {
        assert!(matches!(
            SessionDedup::new(DedupLimits {
                max_flows: 0,
                ..DedupLimits::default()
            }),
            Err(DedupError::InvalidLimits)
        ));
        // Silence unused import in this scope on minimal builds.
        let _ = DeviceId::from_bytes([0; 16]);
    }

    #[test]
    fn duplicate_within_one_key_is_dropped_first_valid_wins() {
        let mut dedup = SessionDedup::new(DedupLimits::default()).unwrap();
        let key = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(
            dedup.observe(key, PacketId::new(7), 100),
            DedupOutcome::New
        );
        assert_eq!(
            dedup.observe(key, PacketId::new(7), 101),
            DedupOutcome::Duplicate
        );
        assert_eq!(dedup.metrics().packets_seen, 1);
        assert_eq!(dedup.metrics().duplicates_dropped, 1);
    }

    #[test]
    fn complete_key_isolates_sessions_directions_epochs_and_flows() {
        let mut dedup = SessionDedup::new(DedupLimits::default()).unwrap();
        let base = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(dedup.observe(base, PacketId::new(3), 0), DedupOutcome::New);
        // Same packet ID under a different session, direction, epoch, or
        // flow is a different packet, never a duplicate.
        for other in [
            key(SESSION_B, Direction::ClientToGateway, 9, 1),
            key(SESSION_A, Direction::GatewayToClient, 9, 1),
            key(SESSION_A, Direction::ClientToGateway, 10, 1),
            key(SESSION_A, Direction::ClientToGateway, 9, 2),
        ] {
            assert_eq!(
                dedup.observe(other, PacketId::new(3), 1),
                DedupOutcome::New,
                "key {other:?} must be isolated"
            );
        }
        assert_eq!(dedup.flow_count(), 5);
    }

    #[test]
    fn flow_packet_bound_evicts_oldest_and_counts() {
        let mut dedup = SessionDedup::new(DedupLimits {
            max_flows: 8,
            max_packets_per_flow: 2,
            flow_idle_ttl_ms: 1_000,
            ..DedupLimits::default()
        })
        .unwrap();
        let key = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(dedup.observe(key, PacketId::new(1), 0), DedupOutcome::New);
        assert_eq!(dedup.observe(key, PacketId::new(2), 1), DedupOutcome::New);
        // Full: inserting a third evicts the smallest (1) and stays New.
        assert_eq!(dedup.observe(key, PacketId::new(3), 2), DedupOutcome::New);
        assert_eq!(dedup.metrics().packets_evicted_capacity, 1);
        // Evicted ID 1 may be re-accepted here; the reorder prefix guard
        // still drops it as stale downstream. The table stays bounded.
        assert_eq!(dedup.observe(key, PacketId::new(1), 3), DedupOutcome::New);
        assert_eq!(dedup.metrics().packets_evicted_capacity, 2);
    }

    #[test]
    fn session_flow_bound_evicts_oldest_and_expire_removes_idle() {
        let mut dedup = SessionDedup::new(DedupLimits {
            max_flows: 2,
            max_packets_per_flow: 4,
            flow_idle_ttl_ms: 10,
            ..DedupLimits::default()
        })
        .unwrap();
        let a = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        let b = key(SESSION_A, Direction::ClientToGateway, 9, 2);
        let c = key(SESSION_A, Direction::ClientToGateway, 9, 3);
        assert_eq!(dedup.observe(a, PacketId::new(0), 0), DedupOutcome::New);
        assert_eq!(dedup.observe(b, PacketId::new(0), 5), DedupOutcome::New);
        assert_eq!(dedup.observe(c, PacketId::new(0), 6), DedupOutcome::New);
        assert_eq!(dedup.metrics().flows_evicted_capacity, 1);
        assert_eq!(dedup.flow_count(), 2);
        // Flow b idle since 5, flow c since 6; at 15 both exceed the 10ms TTL.
        assert_eq!(dedup.expire(15), 1);
        assert_eq!(dedup.expire(16), 1);
        assert_eq!(dedup.flow_count(), 0);
        assert_eq!(dedup.metrics().flows_expired_idle, 2);
        let debug = format!("{dedup:?}");
        assert!(!debug.contains("A1A1"));
    }

    #[test]
    fn replay_after_flow_eviction_is_dropped_by_tombstone() {
        let mut dedup = SessionDedup::new(DedupLimits {
            max_flows: 2,
            max_packets_per_flow: 8,
            flow_idle_ttl_ms: 10_000,
            max_tombstones: 8,
            tombstone_ttl_ms: 60_000,
        })
        .unwrap();
        let a = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        let b = key(SESSION_A, Direction::ClientToGateway, 9, 2);
        let c = key(SESSION_A, Direction::ClientToGateway, 9, 3);
        assert_eq!(dedup.observe(a, PacketId::new(0), 0), DedupOutcome::New);
        assert_eq!(dedup.observe(b, PacketId::new(0), 1), DedupOutcome::New);
        // Inserting c evicts the oldest flow (a) and installs a tombstone
        // with watermark 0.
        assert_eq!(dedup.observe(c, PacketId::new(0), 2), DedupOutcome::New);
        assert_eq!(dedup.metrics().flows_evicted_capacity, 1);
        assert_eq!(dedup.tombstone_count(), 1);
        // Replay of the evicted ID is a tombstone duplicate, never a new
        // first arrival; no new flow is opened.
        assert_eq!(
            dedup.observe(a, PacketId::new(0), 3),
            DedupOutcome::Duplicate
        );
        assert_eq!(dedup.metrics().tombstone_hits, 1);
        assert_eq!(dedup.metrics().duplicates_dropped, 1);
        assert_eq!(dedup.flow_count(), 2);
        // An ID strictly beyond the watermark resurrects the key as genuinely
        // new data and clears that tombstone (evicting the next-oldest flow).
        assert_eq!(dedup.observe(a, PacketId::new(1), 4), DedupOutcome::New);
        assert_eq!(dedup.metrics().packets_seen, 4);
        assert_eq!(dedup.flow_count(), 2);
        assert!(dedup.tombstone_count() <= 2, "tombstones stay bounded");
    }

    #[test]
    fn replay_after_idle_expiry_is_dropped_until_tombstone_ttl() {
        let mut dedup = SessionDedup::new(DedupLimits {
            max_flows: 8,
            max_packets_per_flow: 8,
            flow_idle_ttl_ms: 10,
            max_tombstones: 8,
            tombstone_ttl_ms: 20,
        })
        .unwrap();
        let flow = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(dedup.observe(flow, PacketId::new(5), 0), DedupOutcome::New);
        assert_eq!(dedup.expire(10), 1, "flow idle-expires at 10ms");
        assert_eq!(dedup.flow_count(), 0);
        assert_eq!(dedup.tombstone_count(), 1);
        // Tombstone live until 30ms: replay is still a duplicate.
        assert_eq!(
            dedup.observe(flow, PacketId::new(5), 15),
            DedupOutcome::Duplicate
        );
        assert_eq!(dedup.metrics().tombstone_hits, 1);
        assert_eq!(dedup.flow_count(), 0, "replay must not reopen the flow");
        // After the tombstone TTL the key is forgotten and the same ID may
        // open a fresh flow (bounded memory requires eventual forgetting).
        assert_eq!(
            dedup.observe(flow, PacketId::new(5), 30),
            DedupOutcome::New
        );
        assert_eq!(dedup.flow_count(), 1);
    }

    #[test]
    fn tombstone_table_stays_bounded_and_counts_evictions() {
        let mut dedup = SessionDedup::new(DedupLimits {
            max_flows: 1,
            max_packets_per_flow: 4,
            flow_idle_ttl_ms: 10_000,
            max_tombstones: 2,
            tombstone_ttl_ms: 60_000,
        })
        .unwrap();
        for flow_id in [1u64, 2, 3, 4] {
            let flow = key(SESSION_A, Direction::ClientToGateway, 9, flow_id);
            assert_eq!(
                dedup.observe(flow, PacketId::new(0), flow_id),
                DedupOutcome::New
            );
        }
        assert_eq!(dedup.flow_count(), 1);
        assert_eq!(dedup.tombstone_count(), 2, "tombstones capped at 2");
        assert_eq!(dedup.metrics().tombstones_evicted_capacity, 1);
        // The surviving tombstones still guard their keys.
        let evicted = key(SESSION_A, Direction::ClientToGateway, 9, 3);
        assert_eq!(
            dedup.observe(evicted, PacketId::new(0), 10),
            DedupOutcome::Duplicate
        );
    }

    #[test]
    fn tombstone_eviction_with_equal_expiry_and_watermark_is_deterministic() {
        // Same shape as the reorder tie test: max_flows 1 chains evictions so
        // the fourth key forces a tie eviction with identical expiry and
        // watermark. Fresh maps per iteration defeat HashMap RandomState luck.
        for _ in 0..32 {
            let mut dedup = SessionDedup::new(DedupLimits {
                max_flows: 1,
                max_packets_per_flow: 4,
                flow_idle_ttl_ms: 10_000,
                max_tombstones: 2,
                tombstone_ttl_ms: 60_000,
            })
            .unwrap();
            let a = key(SESSION_A, Direction::ClientToGateway, 9, 1);
            let b = key(SESSION_A, Direction::ClientToGateway, 9, 2);
            let c = key(SESSION_A, Direction::ClientToGateway, 9, 3);
            let d = key(SESSION_A, Direction::ClientToGateway, 9, 4);
            for flow in [a, b, c, d] {
                assert_eq!(
                    dedup.observe(flow, PacketId::new(7), 0),
                    DedupOutcome::New
                );
            }
            assert_eq!(dedup.tombstone_count(), 2);
            assert_eq!(dedup.metrics().tombstones_evicted_capacity, 1);
            // Deterministic victim is the smallest key (flow 1): B stays
            // guarded (non-mutating duplicate) while A was forgotten.
            assert_eq!(
                dedup.observe(b, PacketId::new(7), 1),
                DedupOutcome::Duplicate,
                "flow 2 tombstone must survive the tie eviction"
            );
            assert_eq!(
                dedup.observe(a, PacketId::new(7), 2),
                DedupOutcome::New,
                "flow 1 was the deterministic tie victim and may start fresh"
            );
        }
    }
}
