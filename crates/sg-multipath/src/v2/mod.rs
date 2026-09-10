//! V2 per-flow packet delivery: classification, dedup, and deadline reorder.
//!
//! This module is strictly separate from the V1 session-global
//! [`crate::ReorderBuffer`] (spec 11.2/11.3 experimental). V1 remains untouched
//! for development tests until the V2 cutover policy is satisfied.
//!
//! # PacketId strict monotonic contract
//!
//! A [`PacketId`](sg_core::v2::PacketId) is scoped to one [`ReceiveKey`]
//! (session plus direction plus key epoch plus flow) and one traffic class.
//! The sender MUST allocate packet IDs as a strictly increasing sequence per
//! key, advancing by exactly one per originated packet:
//!
//! ```text
//! first_id, first_id + 1, first_id + 2, ...
//! ```
//!
//! - The first observed ID establishes the flow base and is delivered
//!   immediately; unlike V1 there is no requirement to start at zero and no
//!   session-global head that can block unrelated flows.
//! - IDs MUST NOT repeat, go backwards, or skip except through loss or
//!   intentional redundant copies carrying the same ID on another path.
//! - IDs never wrap within a key. Delivering `u64::MAX` terminates the key:
//!   every later arrival for the same key is dropped as exhausted and the
//!   sender MUST rotate the key epoch to continue.
//! - Rotating the key epoch starts a new [`ReceiveKey`]; the old key's state
//!   expires through the flow idle TTL instead of being reused.
//! - Redundant copies MUST reuse the same packet ID. The receiver applies
//!   first-valid-wins: the first arrival is kept and later copies are dropped
//!   and counted as duplicates, regardless of which path delivered first.
//!
//! The receiver enforces this contract without panicking and without blocking
//! unrelated flows:
//!
//! - `packet_id < next_expected` is a duplicate of delivered or skipped data.
//! - `packet_id` already buffered is a duplicate of held data.
//! - Gaps are held only until the traffic-class deadline, then skipped and
//!   counted; later packets are released instead of blocking forever.
//! - Arrivals with `packet_id - next_expected > max_future_gap` are dropped as
//!   far-ahead without allocating state.
//! - Evicted/expired flows leave bounded tombstone high-watermarks: replays at
//!   or below the watermark are dropped as duplicates and can never resurrect
//!   the flow as a first arrival.
//!
//! # Receive key and class immutability
//!
//! Delivery state is keyed by the complete [`ReceiveKey`]: session ID,
//! direction, key epoch, and flow ID. Path ID and path epoch are transport
//! bindings validated before admission and are deliberately NOT part of the
//! delivery key, because one packet ID may legitimately arrive on any healthy
//! path. Traffic class is immutable per key: the first valid arrival fixes the
//! class and later arrivals claiming another class are dropped as mismatches.
//!
//! # Bounds and time
//!
//! Every flow is bounded by packet count, buffered bytes, and age; the session
//! is bounded by flow count and total buffered bytes. Inactive flows expire
//! through an explicit `expire(now_ms)` driven by the engine's monotonic
//! millisecond clock. Tests never rely on wall-clock sleeps for correctness.
//!
//! # Observability
//!
//! Metrics count packets, bytes, drops by reason, skips, evictions, and
//! expiries. They never contain packet payloads, IP addresses, ports, or
//! destination history. `Debug` impls in this module emit lengths and counts
//! only.

pub mod classifier;
pub mod dedup;
pub mod reorder;

pub use classifier::{Classification, Classifier, ClassifierMetrics, ClassifyError};
pub use dedup::{DedupError, DedupLimits, DedupMetrics, DedupOutcome, SessionDedup};
pub use reorder::{
    DropReason, ExpireReport, ReorderError, ReorderLimits, ReorderMetrics, ReorderOutcome,
    SessionReorder,
};

use sg_core::v2::{FlowId, SessionId};
use sg_protocol::v2::Direction;

/// Complete V2 receive key for delivery state.
///
/// Keyed by session plus flow ID, never only session, so a lost packet in one
/// flow can never block an unrelated flow (no cross-flow head-of-line
/// blocking). Direction and key epoch prevent accidental cross-direction or
/// cross-rotation packet identity reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiveKey {
    /// Full-width server-issued session identity.
    pub session: SessionId,
    /// Tunnel direction this packet was received on.
    pub direction: Direction,
    /// Key epoch the packet was sealed under.
    pub key_epoch: u32,
    /// Flow identity within the session.
    pub flow: FlowId,
}

impl ReceiveKey {
    /// Builds a receive key. All four fields are required; there is no
    /// wildcard or default that would collapse distinct flows together.
    #[must_use]
    pub const fn new(
        session: SessionId,
        direction: Direction,
        key_epoch: u32,
        flow: FlowId,
    ) -> Self {
        Self {
            session,
            direction,
            key_epoch,
            flow,
        }
    }

    /// Total deterministic order for tie-breaking bounded evictions.
    ///
    /// `HashMap` iteration order is randomized per instance, so any eviction
    /// that stops at `(expiry, watermark)` is nondeterministic when both tie.
    /// This order (session bytes, direction wire value, key epoch, flow ID)
    /// is a pure function of the key and makes the victim independent of
    /// map order. It is only used to break ties after expiry/watermark.
    pub(crate) fn deterministic_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.session
            .as_bytes()
            .cmp(other.session.as_bytes())
            .then_with(|| {
                self.direction
                    .to_wire()
                    .cmp(&other.direction.to_wire())
            })
            .then_with(|| self.key_epoch.cmp(&other.key_epoch))
            .then_with(|| self.flow.get().cmp(&other.flow.get()))
    }
}
