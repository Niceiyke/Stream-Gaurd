//! Per-flow deadline reorder with first-valid-wins dedup and no cross-flow HOL.
//!
//! [`SessionReorder`] holds one ordered queue per complete
//! [`ReceiveKey`](super::ReceiveKey) (session, direction, key epoch, flow).
//! A missing packet delays only its own flow: other flows deliver immediately.
//! Within a flow the receiver holds out-of-order packets until the gap fills
//! or the traffic-class deadline expires, at which point the gap is skipped,
//! counted, and later packets are released.
//!
//! # PacketId contract (receiver view)
//!
//! The sender allocates IDs strictly increasing by one per receive key (see
//! [`super`] for the full contract). The first observed ID for a key
//! establishes that flow's base and is delivered immediately, so flows may
//! start at any ID. Thereafter:
//!
//! - `id < next_expected` was already delivered or skipped: dropped as a
//!   duplicate and counted.
//! - `id` already buffered: dropped as a duplicate; the held (first) payload
//!   wins and is never replaced.
//! - `id == next_expected`: delivered along with any newly contiguous chain.
//! - `id > next_expected`: buffered subject to packet/byte/future-window
//!   bounds, or dropped with an explicit [`DropReason`] when a bound is hit.
//!
//! # Future window
//!
//! A numeric future window (`max_future_gap`) bounds how far ahead of
//! `next_expected` an arrival may be buffered. Arrivals with
//! `id - next_expected > max_future_gap` are dropped as
//! [`DropReason::FarAhead`] without allocating state, so a single far-future
//! ID can never pin a huge gap skip or inflate `packets_skipped`.
//!
//! # ID exhaustion (no wrap)
//!
//! Packet IDs are `u64` and never wrap within a key. When `next_expected`
//! reaches `u64::MAX`, delivering that final ID terminates the key: the flow
//! is marked exhausted and every later arrival for the same key is dropped as
//! [`DropReason::Exhausted`]. The sender MUST rotate the key epoch (a new
//! [`ReceiveKey`](super::ReceiveKey)) to continue; the old key expires through
//! the flow idle TTL instead of being reused.
//!
//! # Replay-safe eviction and expiry
//!
//! Evicting or expiring a whole flow installs a bounded per-key tombstone
//! holding the flow's high-watermark (maximum observed packet ID) until
//! `tombstone_ttl_ms`. A replay at or below the watermark is dropped as a
//! duplicate and can never resurrect the flow as a first arrival. Only an ID
//! strictly beyond the watermark clears the tombstone and opens a fresh flow.
//! Tombstones are bounded by `max_tombstones` with TTL expiry, so replay
//! protection never grows unbounded state.
//!
//! # Class immutability
//!
//! The first valid arrival fixes the flow's [`TrafficClass`](sg_core::v2::TrafficClass).
//! Later arrivals claiming another class are dropped as
//! [`DropReason::ClassMismatch`] without touching flow state, so a sender (or
//! attacker) cannot upgrade bulk into realtime deadlines mid-flow. The
//! datagram `Control` class is never valid here: control travels on the
//! reliable stream and any such arrival is a mismatch.
//!
//! # Bounds and time
//!
//! Each flow is bounded by packet count and buffered bytes; the session is
//! bounded by flow count and total buffered bytes. When the session flow table
//! is full the least-recently-active flow is evicted and counted. Inactive
//! flows expire through explicit `expire(now_ms)` driven by the engine's
//! monotonic millisecond clock; there is no background thread and no
//! wall-clock sleep in tests.
//!
//! Metrics count outcomes only and never contain payloads, addresses, or
//! destination history. `Debug` emits counts and lengths, never packet bytes.

use std::collections::{BTreeMap, HashMap};

use bytes::Bytes;
use sg_core::v2::{PacketId, TrafficClass};
use thiserror::Error;

use super::ReceiveKey;

/// Bounded reorder limits. Every field is a strict upper bound or TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReorderLimits {
    /// Maximum distinct flows held at once.
    pub max_flows: usize,
    /// Maximum buffered (out-of-order) packets per flow.
    pub max_packets_per_flow: usize,
    /// Maximum buffered bytes per flow.
    pub max_bytes_per_flow: usize,
    /// Maximum buffered bytes across the whole session.
    pub max_bytes_per_session: usize,
    /// Milliseconds after last activity before a flow expires.
    pub flow_idle_ttl_ms: u64,
    /// Realtime gap deadline: small, missed audio/video is skipped fast.
    pub realtime_deadline_ms: u64,
    /// Interactive gap deadline: bounded typing/echo tolerance.
    pub interactive_deadline_ms: u64,
    /// Bulk gap deadline: larger, TCP still recovers end to end.
    pub bulk_deadline_ms: u64,
    /// Maximum per-key tombstones remembered after flow eviction/expiry.
    pub max_tombstones: usize,
    /// Milliseconds a tombstone high-watermark is retained.
    pub tombstone_ttl_ms: u64,
    /// Maximum `packet_id - next_expected` buffered before `FarAhead` drop.
    pub max_future_gap: u64,
}

impl ReorderLimits {
    /// Conservative Safe Mode default: 256 flows, 64 packets / 256 KiB per
    /// flow, 4 MiB per session, 30 s flow TTL, 20/100/500 ms deadlines,
    /// 256 tombstones for 60 s, and a 1024-ID future window.
    #[must_use]
    pub const fn default_limits() -> Self {
        Self {
            max_flows: 256,
            max_packets_per_flow: 64,
            max_bytes_per_flow: 256 * 1024,
            max_bytes_per_session: 4 * 1024 * 1024,
            flow_idle_ttl_ms: 30_000,
            realtime_deadline_ms: 20,
            interactive_deadline_ms: 100,
            bulk_deadline_ms: 500,
            max_tombstones: 256,
            tombstone_ttl_ms: 60_000,
            max_future_gap: 1_024,
        }
    }

    fn validate(self) -> Result<(), ReorderError> {
        if self.max_flows == 0
            || self.max_packets_per_flow == 0
            || self.max_bytes_per_flow == 0
            || self.max_bytes_per_session == 0
            || self.flow_idle_ttl_ms == 0
            || self.realtime_deadline_ms == 0
            || self.interactive_deadline_ms == 0
            || self.bulk_deadline_ms == 0
            || self.max_tombstones == 0
            || self.tombstone_ttl_ms == 0
            || self.max_future_gap == 0
        {
            return Err(ReorderError::InvalidLimits);
        }
        Ok(())
    }

    #[must_use]
    const fn deadline_for(self, class: TrafficClass) -> u64 {
        match class {
            TrafficClass::Realtime | TrafficClass::Control => self.realtime_deadline_ms,
            TrafficClass::Interactive => self.interactive_deadline_ms,
            TrafficClass::Bulk => self.bulk_deadline_ms,
        }
    }
}

impl Default for ReorderLimits {
    fn default() -> Self {
        Self::default_limits()
    }
}

/// Why reorder limits could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ReorderError {
    /// A limit or deadline was zero.
    #[error("reorder limits and deadlines must all be nonzero")]
    InvalidLimits,
}

/// Why one arrival was dropped without delivery or buffering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Already delivered, skipped, or held: first-valid-wins.
    Duplicate,
    /// Traffic class differs from the flow's fixed class (including any
    /// datagram claiming `Control`).
    ClassMismatch,
    /// Flow already holds `max_packets_per_flow` out-of-order packets.
    FlowPacketCapacity,
    /// Buffering would exceed `max_bytes_per_flow`.
    FlowByteCapacity,
    /// Buffering would exceed `max_bytes_per_session`.
    SessionByteCapacity,
    /// Gap beyond `max_future_gap`: never buffered, never skipped over.
    FarAhead,
    /// Key packet-ID space exhausted (`u64::MAX` delivered): rotate epoch.
    Exhausted,
}

/// Outcome of one [`SessionReorder::receive`] call.
#[derive(Clone, PartialEq, Eq)]
pub struct ReorderOutcome {
    /// Payloads that became deliverable, in ascending packet-ID order.
    pub delivered: Vec<(PacketId, Bytes)>,
    /// True when the arrival was accepted and is held awaiting its gap.
    pub buffered: bool,
    /// Set exactly when the arrival was dropped.
    pub dropped: Option<DropReason>,
}

impl std::fmt::Debug for ReorderOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: packet IDs identify wire positions and `Bytes` would emit
        // payload content. Logs and diagnostics only get counts and lengths.
        let delivered_lens: Vec<usize> =
            self.delivered.iter().map(|(_, payload)| payload.len()).collect();
        let delivered_bytes: usize = delivered_lens.iter().sum();
        formatter
            .debug_struct("ReorderOutcome")
            .field("delivered_packets", &self.delivered.len())
            .field("delivered_bytes", &delivered_bytes)
            .field("delivered_lens", &delivered_lens)
            .field("buffered", &self.buffered)
            .field("dropped", &self.dropped)
            .finish()
    }
}

impl ReorderOutcome {
    fn delivered(delivered: Vec<(PacketId, Bytes)>) -> Self {
        Self {
            delivered,
            buffered: false,
            dropped: None,
        }
    }

    fn buffered() -> Self {
        Self {
            delivered: Vec::new(),
            buffered: true,
            dropped: None,
        }
    }

    fn dropped(reason: DropReason) -> Self {
        Self {
            delivered: Vec::new(),
            buffered: false,
            dropped: Some(reason),
        }
    }
}

/// Aggregate reorder outcomes. Counts only; no packet content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReorderMetrics {
    /// Flows currently held.
    pub flows: usize,
    /// Tombstones currently remembered (bounded replay guards).
    pub tombstones: usize,
    /// Buffered packets across all flows.
    pub buffered_packets: usize,
    /// Buffered bytes across all flows.
    pub buffered_bytes: usize,
    /// Total payloads delivered (including via gap skip).
    pub delivered: u64,
    /// Arrivals dropped as duplicates of delivered, skipped, or held data.
    pub duplicates_dropped: u64,
    /// Replays dropped by a tombstone high-watermark (subset of duplicates).
    pub tombstone_hits: u64,
    /// Arrivals dropped for claiming another traffic class.
    pub class_mismatch_dropped: u64,
    /// Arrivals dropped because their flow packet window was full.
    pub flow_packet_capacity_dropped: u64,
    /// Arrivals dropped because their flow byte window was full.
    pub flow_byte_capacity_dropped: u64,
    /// Arrivals dropped because the session byte window was full.
    pub session_byte_capacity_dropped: u64,
    /// Arrivals dropped for exceeding `max_future_gap`.
    pub far_ahead_dropped: u64,
    /// Arrivals dropped because the key packet-ID space is exhausted.
    pub exhausted_dropped: u64,
    /// Head gaps skipped after their deadline.
    pub gaps_skipped: u64,
    /// Missing packet IDs skipped over.
    pub packets_skipped: u64,
    /// Flows evicted because the session flow table was full.
    pub flows_evicted_capacity: u64,
    /// Flows removed by idle TTL.
    pub flows_expired_idle: u64,
    /// Tombstones evicted because the tombstone table was full.
    pub tombstones_evicted_capacity: u64,
    /// Tombstones removed by TTL expiry.
    pub tombstones_expired: u64,
}

/// What one [`SessionReorder::expire`] call released or reaped.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExpireReport {
    /// Payloads released by gap skips, grouped per arrival order within each
    /// flow. Keys are included so tests can assert per-flow progress; they
    /// are never emitted into metrics or logs.
    pub delivered: Vec<(ReceiveKey, PacketId, Bytes)>,
    /// Head gaps skipped by deadline.
    pub gaps_skipped: u64,
    /// Missing packet IDs skipped over.
    pub packets_skipped: u64,
    /// Flows removed by idle TTL.
    pub flows_expired: usize,
}

impl std::fmt::Debug for ExpireReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: receive keys carry session/flow identity, packet IDs carry
        // wire positions, and `Bytes` would emit payload content. Only counts
        // and payload lengths are observable.
        let delivered_lens: Vec<usize> =
            self.delivered.iter().map(|(_, _, payload)| payload.len()).collect();
        let delivered_bytes: usize = delivered_lens.iter().sum();
        formatter
            .debug_struct("ExpireReport")
            .field("delivered_packets", &self.delivered.len())
            .field("delivered_bytes", &delivered_bytes)
            .field("delivered_lens", &delivered_lens)
            .field("gaps_skipped", &self.gaps_skipped)
            .field("packets_skipped", &self.packets_skipped)
            .field("flows_expired", &self.flows_expired)
            .finish()
    }
}

struct BufferedPacket {
    payload: Bytes,
    arrived_at_ms: u64,
}

impl std::fmt::Debug for BufferedPacket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BufferedPacket")
            .field("payload_len", &self.payload.len())
            .field("arrived_at_ms", &self.arrived_at_ms)
            .finish()
    }
}

struct FlowState {
    traffic_class: TrafficClass,
    next_expected: u64,
    /// True once `u64::MAX` has been delivered: no further ID is valid in
    /// this key and every later arrival is dropped as `Exhausted`.
    exhausted: bool,
    buffer: BTreeMap<u64, BufferedPacket>,
    buffered_bytes: usize,
    last_activity_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct ReorderTombstone {
    /// Maximum packet ID observed for the evicted/expired key.
    watermark: u64,
    /// Monotonic time when the tombstone expires.
    expires_at_ms: u64,
}

/// Bounded per-flow reorder keyed by the complete receive key.
pub struct SessionReorder {
    limits: ReorderLimits,
    flows: HashMap<ReceiveKey, FlowState>,
    tombstones: HashMap<ReceiveKey, ReorderTombstone>,
    buffered_bytes_session: usize,
    metrics: ReorderMetrics,
}

impl std::fmt::Debug for SessionReorder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Intentionally redacted: flow keys identify sessions and must not
        // appear in logs; buffered payloads never appear either.
        formatter
            .debug_struct("SessionReorder")
            .field("metrics", &self.metrics())
            .finish()
    }
}

impl SessionReorder {
    /// Creates an empty session reorder table.
    pub fn new(limits: ReorderLimits) -> Result<Self, ReorderError> {
        limits.validate()?;
        Ok(Self {
            limits,
            flows: HashMap::new(),
            tombstones: HashMap::new(),
            buffered_bytes_session: 0,
            metrics: ReorderMetrics::default(),
        })
    }

    /// Feeds one arrival into its flow at `now_ms`.
    ///
    /// Cross-flow isolation: only the named flow is touched, so loss in one
    /// flow never delays another. First-valid-wins: repeats of delivered,
    /// skipped, or held IDs are dropped without replacing the kept payload.
    pub fn receive(
        &mut self,
        key: ReceiveKey,
        traffic_class: TrafficClass,
        packet_id: PacketId,
        payload: Bytes,
        now_ms: u64,
    ) -> ReorderOutcome {
        // Control never rides datagrams; treat it as a class violation rather
        // than opening a control-classed flow.
        if traffic_class == TrafficClass::Control {
            self.metrics.class_mismatch_dropped =
                self.metrics.class_mismatch_dropped.saturating_add(1);
            return ReorderOutcome::dropped(DropReason::ClassMismatch);
        }
        let id = packet_id.get();
        if !self.flows.contains_key(&key) {
            // Replay-safe resurrection: a live tombstone rejects replays at or
            // below its high-watermark so they can never become first
            // arrivals. Only IDs strictly beyond the watermark open a fresh
            // flow; expired tombstones are forgotten.
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
                    return ReorderOutcome::dropped(DropReason::Duplicate);
                } else {
                    self.tombstones.remove(&key);
                }
            }
            if self.flows.len() >= self.limits.max_flows {
                self.evict_oldest_flow(now_ms);
            }
            // No wrap: delivering `u64::MAX` terminates the key. The sender
            // must rotate the key epoch for further packets.
            let (next_expected, exhausted) = if id == u64::MAX {
                (u64::MAX, true)
            } else {
                (id.saturating_add(1), false)
            };
            self.flows.insert(
                key,
                FlowState {
                    traffic_class,
                    next_expected,
                    exhausted,
                    buffer: BTreeMap::new(),
                    buffered_bytes: 0,
                    last_activity_ms: now_ms,
                },
            );
            self.metrics.delivered = self.metrics.delivered.saturating_add(1);
            self.refresh_counts();
            return ReorderOutcome::delivered(vec![(packet_id, payload)]);
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            unreachable!("flow presence was just checked");
        };
        if flow.exhausted {
            // Terminal key: `u64::MAX` was already delivered. No further ID
            // is valid here; the sender must rotate the key epoch.
            self.metrics.exhausted_dropped =
                self.metrics.exhausted_dropped.saturating_add(1);
            flow.last_activity_ms = now_ms;
            return ReorderOutcome::dropped(DropReason::Exhausted);
        }
        if flow.traffic_class != traffic_class {
            self.metrics.class_mismatch_dropped =
                self.metrics.class_mismatch_dropped.saturating_add(1);
            return ReorderOutcome::dropped(DropReason::ClassMismatch);
        }
        let next = flow.next_expected;
        if id < next {
            // Delivered or skipped prefix under the monotonic contract.
            self.metrics.duplicates_dropped =
                self.metrics.duplicates_dropped.saturating_add(1);
            flow.last_activity_ms = now_ms;
            return ReorderOutcome::dropped(DropReason::Duplicate);
        }
        if flow.buffer.contains_key(&id) {
            self.metrics.duplicates_dropped =
                self.metrics.duplicates_dropped.saturating_add(1);
            flow.last_activity_ms = now_ms;
            return ReorderOutcome::dropped(DropReason::Duplicate);
        }
        if id == next {
            // Contiguous head. Never wrap: delivering `u64::MAX` terminates
            // the key instead of advancing to zero.
            if next == u64::MAX {
                flow.exhausted = true;
                flow.last_activity_ms = now_ms;
                self.metrics.delivered = self.metrics.delivered.saturating_add(1);
                return ReorderOutcome::delivered(vec![(packet_id, payload)]);
            }
            let mut delivered = vec![(packet_id, payload)];
            flow.next_expected = next.saturating_add(1);
            // Drain any newly contiguous chain without wrapping past MAX.
            while !flow.exhausted {
                let current = flow.next_expected;
                let Some(held) = flow.buffer.remove(&current) else {
                    break;
                };
                self.buffered_bytes_session = self
                    .buffered_bytes_session
                    .saturating_sub(held.payload.len());
                flow.buffered_bytes = flow.buffered_bytes.saturating_sub(held.payload.len());
                delivered.push((PacketId::new(current), held.payload));
                if current == u64::MAX {
                    flow.exhausted = true;
                    break;
                }
                flow.next_expected = current.saturating_add(1);
            }
            flow.last_activity_ms = now_ms;
            self.metrics.delivered = self
                .metrics
                .delivered
                .saturating_add(delivered.len() as u64);
            return ReorderOutcome::delivered(delivered);
        }
        // Gap: enforce the numeric future window before allocating state so a
        // far-future ID can never pin a huge skip.
        let gap = id.saturating_sub(next);
        if gap > self.limits.max_future_gap {
            self.metrics.far_ahead_dropped =
                self.metrics.far_ahead_dropped.saturating_add(1);
            flow.last_activity_ms = now_ms;
            return ReorderOutcome::dropped(DropReason::FarAhead);
        }
        // Gap: buffer subject to packet/byte bounds.
        if flow.buffer.len() >= self.limits.max_packets_per_flow {
            self.metrics.flow_packet_capacity_dropped = self
                .metrics
                .flow_packet_capacity_dropped
                .saturating_add(1);
            flow.last_activity_ms = now_ms;
            return ReorderOutcome::dropped(DropReason::FlowPacketCapacity);
        }
        if flow.buffered_bytes.saturating_add(payload.len()) > self.limits.max_bytes_per_flow {
            self.metrics.flow_byte_capacity_dropped = self
                .metrics
                .flow_byte_capacity_dropped
                .saturating_add(1);
            flow.last_activity_ms = now_ms;
            return ReorderOutcome::dropped(DropReason::FlowByteCapacity);
        }
        if self
            .buffered_bytes_session
            .saturating_add(payload.len())
            > self.limits.max_bytes_per_session
        {
            self.metrics.session_byte_capacity_dropped = self
                .metrics
                .session_byte_capacity_dropped
                .saturating_add(1);
            flow.last_activity_ms = now_ms;
            return ReorderOutcome::dropped(DropReason::SessionByteCapacity);
        }
        let payload_len = payload.len();
        flow.buffer.insert(
            id,
            BufferedPacket {
                payload,
                arrived_at_ms: now_ms,
            },
        );
        flow.buffered_bytes = flow.buffered_bytes.saturating_add(payload_len);
        self.buffered_bytes_session = self.buffered_bytes_session.saturating_add(payload_len);
        flow.last_activity_ms = now_ms;
        // A gap that already outlived its deadline is skipped immediately so
        // a late arrival after a quiet period still releases the flow.
        if let Some(delivered) = self.skip_head_gap_if_expired(key, now_ms) {
            return ReorderOutcome::delivered(delivered);
        }
        ReorderOutcome::buffered()
    }

    /// Advances time: expires idle flows and skips deadline-exceeded head
    /// gaps. Deterministic in `now_ms`; never sleeps.
    ///
    /// Each expired flow installs a tombstone high-watermark so immediate
    /// replays are still dropped. Expired tombstones are reaped in the same
    /// call to keep total state bounded.
    pub fn expire(&mut self, now_ms: u64) -> ExpireReport {
        let mut report = ExpireReport::default();
        let gaps_before = self.metrics.gaps_skipped;
        let skipped_before = self.metrics.packets_skipped;
        self.purge_expired_tombstones(now_ms);
        let ttl = self.limits.flow_idle_ttl_ms;
        let idle: Vec<(ReceiveKey, u64)> = self
            .flows
            .iter()
            .filter(|(_, flow)| now_ms.saturating_sub(flow.last_activity_ms) >= ttl)
            .map(|(key, flow)| (*key, Self::max_observed_for_flow(flow)))
            .collect();
        for (key, watermark) in idle {
            if let Some(flow) = self.flows.remove(&key) {
                self.buffered_bytes_session = self
                    .buffered_bytes_session
                    .saturating_sub(flow.buffered_bytes);
            }
            self.insert_tombstone(key, watermark, now_ms);
            report.flows_expired = report.flows_expired.saturating_add(1);
        }
        self.metrics.flows_expired_idle = self
            .metrics
            .flows_expired_idle
            .saturating_add(report.flows_expired as u64);
        // Deadline skips for the surviving flows, in deterministic key order.
        // A flow may skip several head gaps in one call when each head in
        // turn already outlived its deadline.
        let mut keys: Vec<ReceiveKey> = self.flows.keys().copied().collect();
        keys.sort_by_key(|key| (key.flow.get(), key.key_epoch, key.direction as u8));
        for key in keys {
            while let Some(delivered) = self.skip_head_gap_if_expired(key, now_ms) {
                for (packet_id, payload) in delivered {
                    report.delivered.push((key, packet_id, payload));
                }
            }
        }
        report.gaps_skipped = self.metrics.gaps_skipped.saturating_sub(gaps_before);
        report.packets_skipped = self
            .metrics
            .packets_skipped
            .saturating_sub(skipped_before);
        self.refresh_counts();
        report
    }

    /// Current aggregate metrics with live buffer totals.
    #[must_use]
    pub fn metrics(&self) -> ReorderMetrics {
        let mut metrics = self.metrics;
        metrics.flows = self.flows.len();
        metrics.tombstones = self.tombstones.len();
        metrics.buffered_packets = self.flows.values().map(|flow| flow.buffer.len()).sum();
        metrics.buffered_bytes = self.buffered_bytes_session;
        metrics
    }

    /// Number of flows currently held.
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
            .map(|(key, flow)| (*key, Self::max_observed_for_flow(flow)));
        if let Some((key, watermark)) = oldest {
            if let Some(flow) = self.flows.remove(&key) {
                self.buffered_bytes_session = self
                    .buffered_bytes_session
                    .saturating_sub(flow.buffered_bytes);
            }
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
            ReorderTombstone {
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

    /// Skips the head gap when the oldest held packet outlived the flow
    /// deadline. Returns newly deliverable payloads in ID order, or `None`
    /// when no skip was due. Updates gap/skip metrics and flow clocks.
    fn skip_head_gap_if_expired(
        &mut self,
        key: ReceiveKey,
        now_ms: u64,
    ) -> Option<Vec<(PacketId, Bytes)>> {
        let deadline = {
            let flow = self.flows.get(&key)?;
            if flow.exhausted {
                return None;
            }
            self.limits.deadline_for(flow.traffic_class)
        };
        let (smallest_id, oldest_arrival) = {
            let flow = self.flows.get(&key)?;
            let (id, held) = flow.buffer.iter().next()?;
            if flow.next_expected >= *id {
                return None;
            }
            (*id, held.arrived_at_ms)
        };
        if now_ms.saturating_sub(oldest_arrival) < deadline {
            return None;
        }
        let flow = self.flows.get_mut(&key)?;
        // The future window bounds every buffered gap, so this skip count is
        // bounded by `max_future_gap` and can never inflate `packets_skipped`
        // with a far-future jump.
        let skipped = smallest_id.saturating_sub(flow.next_expected);
        flow.next_expected = smallest_id;
        self.metrics.gaps_skipped = self.metrics.gaps_skipped.saturating_add(1);
        self.metrics.packets_skipped = self.metrics.packets_skipped.saturating_add(skipped);
        let mut delivered = Vec::new();
        while !flow.exhausted {
            let current = flow.next_expected;
            let Some(held) = flow.buffer.remove(&current) else {
                break;
            };
            self.buffered_bytes_session = self
                .buffered_bytes_session
                .saturating_sub(held.payload.len());
            flow.buffered_bytes = flow.buffered_bytes.saturating_sub(held.payload.len());
            delivered.push((PacketId::new(current), held.payload));
            if current == u64::MAX {
                flow.exhausted = true;
                break;
            }
            flow.next_expected = current.saturating_add(1);
        }
        if delivered.is_empty() {
            return None;
        }
        flow.last_activity_ms = now_ms;
        self.metrics.delivered = self
            .metrics
            .delivered
            .saturating_add(delivered.len() as u64);
        Some(delivered)
    }

    /// Maximum packet ID observed for a flow: the delivered/skipped prefix
    /// head minus one, or the largest buffered ID, whichever is larger.
    /// Exhausted keys report `u64::MAX` so no replay can resurrect them.
    fn max_observed_for_flow(flow: &FlowState) -> u64 {
    if flow.exhausted {
        return u64::MAX;
    }
    let max_delivered = flow.next_expected.saturating_sub(1);
    match flow.buffer.keys().next_back().copied() {
        Some(max_buffered) => max_delivered.max(max_buffered),
        None => max_delivered,
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    use sg_core::v2::{FlowId, SessionId};
    use sg_protocol::v2::Direction;

    use super::super::ReceiveKey;

    const SESSION_A: SessionId = SessionId::from_bytes([0xA1; 16]);
    const SESSION_B: SessionId = SessionId::from_bytes([0xB2; 16]);

    fn key(session: SessionId, direction: Direction, key_epoch: u32, flow: u64) -> ReceiveKey {
        ReceiveKey::new(session, direction, key_epoch, FlowId::new(flow))
    }

    fn limits() -> ReorderLimits {
        ReorderLimits {
            max_flows: 8,
            max_packets_per_flow: 8,
            max_bytes_per_flow: 1_024,
            max_bytes_per_session: 4_096,
            flow_idle_ttl_ms: 1_000,
            realtime_deadline_ms: 20,
            interactive_deadline_ms: 100,
            bulk_deadline_ms: 500,
            max_tombstones: 8,
            tombstone_ttl_ms: 5_000,
            max_future_gap: 1_024,
        }
    }

    fn payload(text: &'static str) -> Bytes {
        Bytes::from_static(text.as_bytes())
    }

    #[test]
    fn invalid_limits_are_rejected() {
        assert!(matches!(
            SessionReorder::new(ReorderLimits {
                max_flows: 0,
                ..limits()
            }),
            Err(ReorderError::InvalidLimits)
        ));
    }

    #[test]
    fn loss_in_flow_a_does_not_delay_flow_b() {
        let mut session = SessionReorder::new(limits()).unwrap();
        let a = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        let b = key(SESSION_A, Direction::ClientToGateway, 9, 2);
        // Flow A opens at 0, then jumps to 2 (1 lost).
        assert_eq!(
            session
                .receive(a, TrafficClass::Bulk, PacketId::new(0), payload("a0"), 0)
                .delivered
                .len(),
            1
        );
        let held = session.receive(a, TrafficClass::Bulk, PacketId::new(2), payload("a2"), 1);
        assert!(held.buffered);
        // Flow B makes independent progress while A waits for its gap.
        for id in 0..4 {
            let outcome = session.receive(
                b,
                TrafficClass::Bulk,
                PacketId::new(id),
                Bytes::from(vec![id as u8]),
                2,
            );
            assert_eq!(outcome.delivered.len(), 1, "flow B packet {id} delivers");
            assert!(!outcome.buffered);
        }
        assert_eq!(session.metrics().buffered_packets, 1);
    }

    #[test]
    fn duplicate_first_delivery_wins_and_late_copies_drop() {
        let mut session = SessionReorder::new(limits()).unwrap();
        let flow = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(
            session
                .receive(flow, TrafficClass::Bulk, PacketId::new(0), payload("first"), 0)
                .delivered
                .len(),
            1
        );
        // Redundant copy with a different payload loses: first-valid-wins.
        let outcome = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(0),
            payload("second"),
            1,
        );
        assert_eq!(outcome.dropped, Some(DropReason::Duplicate));
        // Duplicate of a held packet also drops without replacing it.
        assert!(session
            .receive(flow, TrafficClass::Bulk, PacketId::new(2), payload("held"), 2)
            .buffered);
        let duplicate_held = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(2),
            payload("held-copy"),
            3,
        );
        assert_eq!(duplicate_held.dropped, Some(DropReason::Duplicate));
        // Filling the gap releases the original held payload, not the copy.
        let released = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(1),
            payload("gap"),
            4,
        );
        assert_eq!(released.delivered.len(), 2);
        assert_eq!(released.delivered[1].1, payload("held"));
        assert_eq!(session.metrics().duplicates_dropped, 2);
    }

    #[test]
    fn reorder_deadlines_release_later_packets_when_gap_expires() {
        let mut session = SessionReorder::new(limits()).unwrap();
        let realtime = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(
            session
                .receive(
                    realtime,
                    TrafficClass::Realtime,
                    PacketId::new(0),
                    payload("r0"),
                    0
                )
                .delivered
                .len(),
            1
        );
        assert!(session
            .receive(
                realtime,
                TrafficClass::Realtime,
                PacketId::new(2),
                payload("r2"),
                1
            )
            .buffered);
        assert!(session
            .receive(
                realtime,
                TrafficClass::Realtime,
                PacketId::new(3),
                payload("r3"),
                2
            )
            .buffered);
        // Realtime deadline is 20ms; at 21ms the head gap (missing 1) is
        // skipped and 2..3 release. Metrics record the skip.
        let report = session.expire(21);
        assert!(!report.delivered.is_empty() || session.metrics().gaps_skipped == 1);
        assert_eq!(session.metrics().gaps_skipped, 1);
        assert_eq!(session.metrics().packets_skipped, 1);
        let delivered_ids: Vec<u64> = report
            .delivered
            .iter()
            .map(|(_, id, _)| id.get())
            .collect();
        assert!(delivered_ids.contains(&2) && delivered_ids.contains(&3));
        // A late arrival for the skipped ID is a duplicate, not a resurrection.
        let late = session.receive(
            realtime,
            TrafficClass::Realtime,
            PacketId::new(1),
            payload("late"),
            22,
        );
        assert_eq!(late.dropped, Some(DropReason::Duplicate));
    }

    #[test]
    fn bulk_tolerates_longer_gaps_than_realtime() {
        let mut session = SessionReorder::new(limits()).unwrap();
        let realtime = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        let bulk = key(SESSION_A, Direction::ClientToGateway, 9, 2);
        for (flow, class) in [
            (realtime, TrafficClass::Realtime),
            (bulk, TrafficClass::Bulk),
        ] {
            assert_eq!(
                session
                    .receive(flow, class, PacketId::new(10), payload("base"), 0)
                    .delivered
                    .len(),
                1
            );
            assert!(session
                .receive(flow, class, PacketId::new(12), payload("held"), 1)
                .buffered);
        }
        // At 21ms only realtime expired (deadline 20); bulk (500) still waits.
        let _ = session.expire(21);
        assert_eq!(session.metrics().gaps_skipped, 1);
        // Bulk still holds its gap until its own deadline.
        let bulk_flow = session.flows.get(&bulk).unwrap();
        assert!(bulk_flow.buffer.contains_key(&12));
    }

    #[test]
    fn memory_limits_evict_safely_and_increment_metrics() {
        let mut session = SessionReorder::new(ReorderLimits {
            max_packets_per_flow: 2,
            max_bytes_per_flow: 8,
            max_bytes_per_session: 10,
            ..limits()
        })
        .unwrap();
        let flow = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(
            session
                .receive(flow, TrafficClass::Bulk, PacketId::new(0), payload("base"), 0)
                .delivered
                .len(),
            1
        );
        // Packet window: two held, third exceeds the count bound.
        assert!(session
            .receive(flow, TrafficClass::Bulk, PacketId::new(2), payload("ab"), 1)
            .buffered);
        assert!(session
            .receive(flow, TrafficClass::Bulk, PacketId::new(3), payload("cd"), 2)
            .buffered);
        let capped = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(4),
            payload("ef"),
            3,
        );
        assert_eq!(capped.dropped, Some(DropReason::FlowPacketCapacity));
        // Byte window: a large payload on a fresh flow exceeds the per-flow
        // byte bound before the packet count bound can trigger.
        let byte_flow = key(SESSION_A, Direction::ClientToGateway, 9, 7);
        assert_eq!(
            session
                .receive(
                    byte_flow,
                    TrafficClass::Bulk,
                    PacketId::new(0),
                    payload("b0"),
                    4
                )
                .delivered
                .len(),
            1
        );
        let byte_capped = session.receive(
            byte_flow,
            TrafficClass::Bulk,
            PacketId::new(2),
            Bytes::from(vec![0u8; 64]),
            5,
        );
        assert_eq!(byte_capped.dropped, Some(DropReason::FlowByteCapacity));
        assert!(session.metrics().flow_packet_capacity_dropped >= 1);
        assert!(session.metrics().flow_byte_capacity_dropped >= 1);
        // Session window: a second flow cannot exceed the session byte cap.
        let other = key(SESSION_A, Direction::ClientToGateway, 9, 2);
        assert_eq!(
            session
                .receive(other, TrafficClass::Bulk, PacketId::new(0), payload("o0"), 5)
                .delivered
                .len(),
            1
        );
        let session_capped = session.receive(
            other,
            TrafficClass::Bulk,
            PacketId::new(2),
            Bytes::from(vec![1u8; 8]),
            6,
        );
        assert_eq!(
            session_capped.dropped,
            Some(DropReason::SessionByteCapacity)
        );
    }

    #[test]
    fn traffic_class_is_immutable_per_flow_and_control_never_opens_a_flow() {
        let mut session = SessionReorder::new(limits()).unwrap();
        let flow = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(
            session
                .receive(flow, TrafficClass::Realtime, PacketId::new(5), payload("r"), 0)
                .delivered
                .len(),
            1
        );
        let mismatch = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(6),
            payload("b"),
            1,
        );
        assert_eq!(mismatch.dropped, Some(DropReason::ClassMismatch));
        assert_eq!(session.metrics().class_mismatch_dropped, 1);
        // Control datagrams are rejected even for a fresh key.
        let control_key = key(SESSION_A, Direction::ClientToGateway, 9, 99);
        let control = session.receive(
            control_key,
            TrafficClass::Control,
            PacketId::new(0),
            payload("c"),
            2,
        );
        assert_eq!(control.dropped, Some(DropReason::ClassMismatch));
        assert_eq!(session.flow_count(), 1);
    }

    #[test]
    fn complete_key_and_monotonic_ids_are_enforced() {
        let mut session = SessionReorder::new(limits()).unwrap();
        let base = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        // First ID establishes the base at a nonzero value (no V1 zero rule).
        assert_eq!(
            session
                .receive(base, TrafficClass::Bulk, PacketId::new(41), payload("b"), 0)
                .delivered
                .len(),
            1
        );
        // Backwards IDs are stale duplicates.
        assert_eq!(
            session
                .receive(base, TrafficClass::Bulk, PacketId::new(40), payload("s"), 1)
                .dropped,
            Some(DropReason::Duplicate)
        );
        // Same numeric ID under another session, direction, epoch, or flow
        // is independent state, never a duplicate.
        for other in [
            key(SESSION_B, Direction::ClientToGateway, 9, 1),
            key(SESSION_A, Direction::GatewayToClient, 9, 1),
            key(SESSION_A, Direction::ClientToGateway, 10, 1),
            key(SESSION_A, Direction::ClientToGateway, 9, 2),
        ] {
            let outcome = session.receive(
                other,
                TrafficClass::Bulk,
                PacketId::new(41),
                payload("x"),
                2,
            );
            assert_eq!(outcome.delivered.len(), 1, "key {other:?} isolated");
        }
        assert_eq!(session.flow_count(), 5);
    }

    #[test]
    fn idle_flows_expire_and_session_evicts_oldest_flow_at_capacity() {
        let mut session = SessionReorder::new(ReorderLimits {
            max_flows: 2,
            flow_idle_ttl_ms: 10,
            ..limits()
        })
        .unwrap();
        let a = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        let b = key(SESSION_A, Direction::ClientToGateway, 9, 2);
        let c = key(SESSION_A, Direction::ClientToGateway, 9, 3);
        assert_eq!(
            session
                .receive(a, TrafficClass::Bulk, PacketId::new(0), payload("a"), 0)
                .delivered
                .len(),
            1
        );
        assert_eq!(
            session
                .receive(b, TrafficClass::Bulk, PacketId::new(0), payload("b"), 5)
                .delivered
                .len(),
            1
        );
        // Session holds 2 flows; a third evicts the oldest (a).
        assert_eq!(
            session
                .receive(c, TrafficClass::Bulk, PacketId::new(0), payload("c"), 6)
                .delivered
                .len(),
            1
        );
        assert_eq!(session.metrics().flows_evicted_capacity, 1);
        assert_eq!(session.flow_count(), 2);
        // Both survivors idle out by 16ms.
        let report = session.expire(16);
        assert_eq!(report.flows_expired, 2);
        assert_eq!(session.flow_count(), 0);
        assert_eq!(session.metrics().flows_expired_idle, 2);
    }

    #[test]
    fn metrics_and_debug_never_carry_payloads_or_destinations() {
        let mut session = SessionReorder::new(limits()).unwrap();
        let flow = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        let secret = Bytes::from(vec![0x5E; 16]);
        assert_eq!(
            session
                .receive(flow, TrafficClass::Bulk, PacketId::new(0), secret.clone(), 0)
                .delivered
                .len(),
            1
        );
        assert!(session
            .receive(flow, TrafficClass::Bulk, PacketId::new(2), secret, 1)
            .buffered);
        let debug = format!("{session:?}");
        assert!(!debug.contains("94"), "no payload bytes in Debug");
        let metrics = format!("{:?}", session.metrics());
        assert!(!metrics.contains("A1"));
        assert_eq!(session.metrics().buffered_packets, 1);
        assert_eq!(session.metrics().buffered_bytes, 16);
    }

    #[test]
    fn replay_after_flow_eviction_is_dropped_by_tombstone() {
        let mut session = SessionReorder::new(ReorderLimits {
            max_flows: 2,
            max_tombstones: 8,
            tombstone_ttl_ms: 60_000,
            ..limits()
        })
        .unwrap();
        let a = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        let b = key(SESSION_A, Direction::ClientToGateway, 9, 2);
        let c = key(SESSION_A, Direction::ClientToGateway, 9, 3);
        assert_eq!(
            session
                .receive(a, TrafficClass::Bulk, PacketId::new(10), payload("a"), 0)
                .delivered
                .len(),
            1
        );
        // Buffer out-of-order packets so the high-watermark covers more than
        // the delivered prefix.
        assert!(session
            .receive(a, TrafficClass::Bulk, PacketId::new(12), payload("a12"), 1)
            .buffered);
        assert!(session
            .receive(a, TrafficClass::Bulk, PacketId::new(13), payload("a13"), 2)
            .buffered);
        assert_eq!(
            session
                .receive(b, TrafficClass::Bulk, PacketId::new(0), payload("b"), 3)
                .delivered
                .len(),
            1
        );
        // Inserting c evicts the oldest flow (a, watermark 13).
        assert_eq!(
            session
                .receive(c, TrafficClass::Bulk, PacketId::new(0), payload("c"), 4)
                .delivered
                .len(),
            1
        );
        assert_eq!(session.metrics().flows_evicted_capacity, 1);
        assert_eq!(session.tombstone_count(), 1);
        // Replays at or below the watermark never resurrect the flow, whether
        // they were delivered (10) or only buffered (12, 13).
        for replay in [10, 12, 13] {
            let outcome = session.receive(
                a,
                TrafficClass::Bulk,
                PacketId::new(replay),
                payload("replay"),
                5,
            );
            assert_eq!(
                outcome.dropped,
                Some(DropReason::Duplicate),
                "replay {replay} must drop as duplicate"
            );
        }
        assert_eq!(session.metrics().tombstone_hits, 3);
        assert_eq!(session.flow_count(), 2);
        // An ID strictly beyond the watermark opens a fresh flow.
        let resurrected = session.receive(
            a,
            TrafficClass::Bulk,
            PacketId::new(14),
            payload("new"),
            6,
        );
        assert_eq!(resurrected.delivered.len(), 1);
        assert_eq!(session.flow_count(), 2);
    }

    #[test]
    fn replay_after_idle_expiry_is_dropped_until_tombstone_ttl() {
        let mut session = SessionReorder::new(ReorderLimits {
            flow_idle_ttl_ms: 10,
            tombstone_ttl_ms: 20,
            ..limits()
        })
        .unwrap();
        let flow = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(
            session
                .receive(flow, TrafficClass::Bulk, PacketId::new(7), payload("base"), 0)
                .delivered
                .len(),
            1
        );
        let report = session.expire(10);
        assert_eq!(report.flows_expired, 1);
        assert_eq!(session.flow_count(), 0);
        assert_eq!(session.tombstone_count(), 1);
        // Tombstone live until 30ms: replay stays a duplicate.
        let replay = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(7),
            payload("replay"),
            15,
        );
        assert_eq!(replay.dropped, Some(DropReason::Duplicate));
        assert_eq!(session.flow_count(), 0);
        // After the tombstone TTL the key is forgotten and may start fresh.
        let fresh = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(7),
            payload("fresh"),
            30,
        );
        assert_eq!(fresh.delivered.len(), 1);
        assert_eq!(session.flow_count(), 1);
    }

    #[test]
    fn far_ahead_beyond_window_is_rejected_without_buffering() {
        let mut session = SessionReorder::new(ReorderLimits {
            max_future_gap: 4,
            ..limits()
        })
        .unwrap();
        let flow = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        assert_eq!(
            session
                .receive(flow, TrafficClass::Bulk, PacketId::new(0), payload("base"), 0)
                .delivered
                .len(),
            1
        );
        // Gap exactly at the window edge is still buffered.
        assert!(session
            .receive(flow, TrafficClass::Bulk, PacketId::new(4), payload("edge"), 1)
            .buffered);
        // One past the window is rejected without allocating state.
        let far = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(6),
            payload("far"),
            2,
        );
        assert_eq!(far.dropped, Some(DropReason::FarAhead));
        assert_eq!(session.metrics().far_ahead_dropped, 1);
        assert_eq!(session.metrics().buffered_packets, 1);
        assert_eq!(session.metrics().packets_skipped, 0);
        // Filling the real gap still releases the edge packet.
        let released = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(1),
            payload("gap"),
            3,
        );
        assert_eq!(released.delivered.len(), 1);
    }

    #[test]
    fn u64_max_terminates_key_without_wrap_and_epoch_rotates() {
        let mut session = SessionReorder::new(limits()).unwrap();
        let flow = key(SESSION_A, Direction::ClientToGateway, 9, 1);
        // Base at MAX-1 delivers, then MAX delivers and terminates the key.
        assert_eq!(
            session
                .receive(
                    flow,
                    TrafficClass::Bulk,
                    PacketId::new(u64::MAX - 1),
                    payload("penultimate"),
                    0
                )
                .delivered
                .len(),
            1
        );
        let last = session.receive(
            flow,
            TrafficClass::Bulk,
            PacketId::new(u64::MAX),
            payload("last"),
            1,
        );
        assert_eq!(last.delivered.len(), 1);
        // No wrap to zero: every later arrival for the same key is exhausted,
        // including zero and a repeat of MAX.
        for id in [0, 1, u64::MAX] {
            let outcome = session.receive(
                flow,
                TrafficClass::Bulk,
                PacketId::new(id),
                payload("after"),
                2,
            );
            assert_eq!(
                outcome.dropped,
                Some(DropReason::Exhausted),
                "id {id} after MAX must exhaust, never wrap"
            );
        }
        assert_eq!(session.metrics().exhausted_dropped, 3);
        // A first arrival exactly at MAX also terminates immediately.
        let max_only = key(SESSION_A, Direction::ClientToGateway, 9, 7);
        assert_eq!(
            session
                .receive(
                    max_only,
                    TrafficClass::Bulk,
                    PacketId::new(u64::MAX),
                    payload("solo"),
                    3
                )
                .delivered
                .len(),
            1
        );
        assert_eq!(
            session
                .receive(
                    max_only,
                    TrafficClass::Bulk,
                    PacketId::new(0),
                    payload("wrap"),
                    4
                )
                .dropped,
            Some(DropReason::Exhausted)
        );
        // Rotating the key epoch starts a fresh packet-ID space.
        let rotated = key(SESSION_A, Direction::ClientToGateway, 10, 1);
        assert_eq!(
            session
                .receive(rotated, TrafficClass::Bulk, PacketId::new(0), payload("r0"), 5)
                .delivered
                .len(),
            1
        );
        assert_eq!(
            session
                .receive(rotated, TrafficClass::Bulk, PacketId::new(1), payload("r1"), 6)
                .delivered
                .len(),
            1
        );
    }

    #[test]
    fn reorder_outcome_debug_emits_counts_and_lengths_only() {
        let secret = Bytes::from_static(b"super-secret-payload-XYZ-987");
        assert_eq!(secret.len(), 28);
        let outcome = ReorderOutcome {
            delivered: vec![
                (PacketId::new(3_735_928_559), secret.clone()),
                (PacketId::new(3_131_961_357), secret),
            ],
            buffered: false,
            dropped: None,
        };
        let debug = format!("{outcome:?}");
        assert!(
            debug.contains("delivered_packets"),
            "counts labelled, got {debug}"
        );
        assert!(debug.contains("delivered_bytes"), "got {debug}");
        assert!(debug.contains("delivered_lens"), "got {debug}");
        // Counts and lengths are observable.
        assert!(debug.contains('2'), "packet count, got {debug}");
        assert!(debug.contains("28"), "payload length, got {debug}");
        assert!(debug.contains("56"), "total bytes, got {debug}");
        // Payload content and wire IDs never appear.
        assert!(!debug.contains("super-secret"), "payload leaked: {debug}");
        assert!(!debug.contains("XYZ"), "payload fragment leaked: {debug}");
        assert!(
            !debug.contains("3735928559"),
            "packet ID leaked: {debug}"
        );
        assert!(
            !debug.contains("3131961357"),
            "packet ID leaked: {debug}"
        );
    }

    #[test]
    fn expire_report_debug_emits_counts_and_lengths_only() {
        let session = SessionId::from_bytes([0xC7; 16]);
        let flow_key = key(session, Direction::ClientToGateway, 9, 9_876_543_210);
        let secret = Bytes::from_static(b"super-secret-payload-XYZ-987");
        let report = ExpireReport {
            delivered: vec![(flow_key, PacketId::new(3_735_928_559), secret)],
            gaps_skipped: 1,
            packets_skipped: 1,
            flows_expired: 0,
        };
        let debug = format!("{report:?}");
        assert!(
            debug.contains("delivered_packets"),
            "counts labelled, got {debug}"
        );
        assert!(debug.contains("delivered_bytes"), "got {debug}");
        assert!(debug.contains("delivered_lens"), "got {debug}");
        assert!(debug.contains("28"), "payload length, got {debug}");
        assert!(!debug.contains("super-secret"), "payload leaked: {debug}");
        assert!(!debug.contains("XYZ"), "payload fragment leaked: {debug}");
        assert!(
            !debug.contains("3735928559"),
            "packet ID leaked: {debug}"
        );
        assert!(
            !debug.contains("9876543210"),
            "flow ID leaked: {debug}"
        );
        assert!(
            !debug.contains("199"),
            "session bytes leaked (0xC7 = 199): {debug}"
        );
    }

    #[test]
    fn tombstone_eviction_with_equal_expiry_and_watermark_is_deterministic() {
        // max_flows 1 forces every new key to evict its predecessor; with
        // max_tombstones 2 the fourth key forces a tie eviction where both
        // residents share expiry and watermark. Fresh maps per iteration
        // defeat HashMap RandomState luck: a nondeterministic victim would
        // fail well within 32 tries.
        for _ in 0..32 {
            let mut session = SessionReorder::new(ReorderLimits {
                max_flows: 1,
                max_tombstones: 2,
                tombstone_ttl_ms: 60_000,
                flow_idle_ttl_ms: 10_000,
                ..limits()
            })
            .unwrap();
            let a = key(SESSION_A, Direction::ClientToGateway, 9, 1);
            let b = key(SESSION_A, Direction::ClientToGateway, 9, 2);
            let c = key(SESSION_A, Direction::ClientToGateway, 9, 3);
            let d = key(SESSION_A, Direction::ClientToGateway, 9, 4);
            for flow in [a, b, c, d] {
                let outcome = session.receive(
                    flow,
                    TrafficClass::Bulk,
                    PacketId::new(7),
                    payload("x"),
                    0,
                );
                assert_eq!(outcome.delivered.len(), 1);
            }
            assert_eq!(session.tombstone_count(), 2);
            assert_eq!(session.metrics().tombstones_evicted_capacity, 1);
            // Deterministic victim is the smallest key (flow 1): B stays
            // guarded while A was forgotten. Probe B first (non-mutating
            // duplicate) then A (fresh delivery).
            let probe_b = session.receive(
                b,
                TrafficClass::Bulk,
                PacketId::new(7),
                payload("replay"),
                1,
            );
            assert_eq!(
                probe_b.dropped,
                Some(DropReason::Duplicate),
                "flow 2 tombstone must survive the tie eviction"
            );
            let probe_a = session.receive(
                a,
                TrafficClass::Bulk,
                PacketId::new(7),
                payload("fresh"),
                2,
            );
            assert_eq!(
                probe_a.delivered.len(),
                1,
                "flow 1 was the deterministic tie victim and may start fresh"
            );
        }
    }
}
