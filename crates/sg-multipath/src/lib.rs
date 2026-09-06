//! Multipath scheduling, failover, redundancy, sequencing, deduplication
//! and reordering (spec section 12).
//!
//! Phase 1: active/standby. Phase 2: adaptive redundancy. Phase 3:
//! weighted bonding. The scheduler is the primary differentiating
//! component and owns authoritative path state.

use sg_core::{error::Result, Sequence};
use sg_health::PathMetrics;

/// Which scheduler phase is active (spec section 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerPhase {
    /// Select best healthy path, keep alternates alive, migrate on failure.
    ActiveStandby,
    /// Duplicate selected packets when the active path degrades.
    AdaptiveRedundancy,
    /// Distribute packets by capacity; sequence/dedup/reorder at gateway.
    WeightedBonding,
}

/// Decision the scheduler makes for a given packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Send only via the active path.
    Send { path: u8 },
    /// Send in parallel on the active + redundancy path(s).
    Duplicate { paths: [u8; 2] },
}

/// Feeds scheduler decisions; the engine submits metric updates as
/// they arrive and the scheduler streams out a latest-decision handle.
pub trait Scheduler: Send + Sync {
    /// Updates the scheduler with the latest per-path metrics.
    fn update_metrics(&mut self, metrics: &PathMetrics, path: u8) -> Result<()>;

    /// Chooses how to exit the next queued packet.
    fn decide(&self) -> Decision;

    /// Current phase.
    fn phase(&self) -> SchedulerPhase;
}

/// Monotonic packet sequencer (spec 11.2). One instance per session.
#[derive(Debug, Default)]
pub struct Sequencer {
    next: Sequence,
}

impl Sequencer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves the next sequence number.
    pub fn next_sequence(&mut self) -> Sequence {
        let cur = self.next;
        self.next = Sequence::new(self.next.get().wrapping_add(1));
        cur
    }
}

/// Bounded reorder/dedup window (spec 11.3). Falls back to 100 ms of the
/// worst-case path delta; the scaffold uses a packet count.
pub struct ReorderWindow {
    capacity: usize,
    /// (sequence, idempotent marker) buffer keyed by sequence mod capacity.
    seen: Vec<Option<u64>>,
    last_written: u64,
}

impl ReorderWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            seen: vec![None; capacity.max(1)],
            last_written: 0,
        }
    }

    /// Records a received sequence and returns true if it is a new (non-duplicate)
    /// packet that can be passed up.
    pub fn accept(&mut self, seq: Sequence) -> bool {
        let idx = seq.get() % self.capacity as u64;
        if self.seen[idx as usize] == Some(seq.get()) {
            return false; // duplicate
        }
        self.seen[idx as usize] = Some(seq.get());
        if seq.get() > self.last_written {
            self.last_written = seq.get();
        }
        true
    }
}

/// Convenience constructor for the initial 128-packet window from the spec.
pub fn default_reorder_window() -> ReorderWindow {
    ReorderWindow::new(128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequencer_monotonic() {
        let mut s = Sequencer::new();
        assert_eq!(s.next_sequence(), Sequence::new(0));
        assert_eq!(s.next_sequence(), Sequence::new(1));
        assert_eq!(s.next_sequence(), Sequence::new(2));
    }

    #[test]
    fn reorder_window_dedups() {
        let mut w = default_reorder_window();
        assert!(w.accept(Sequence::new(10)));
        assert!(!w.accept(Sequence::new(10)), "duplicate rejected");
        assert!(w.accept(Sequence::new(11)));
    }
}