//! Multipath scheduling, failover, redundancy, sequencing, deduplication
//! and reordering (spec section 12).
//!
//! Phase 1: active/standby. Phase 2: adaptive redundancy. Phase 3:
//! weighted bonding. The scheduler is the primary differentiating
//! component and owns authoritative path state.

use std::collections::BTreeMap;

use bytes::Bytes;
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

/// Outcome of feeding one arrival into a [ReorderBuffer].
#[derive(Debug, Default)]
pub struct ReorderOutcome {
    /// Payloads that became deliverable, in ascending sequence order. A single
    /// arrival can resolve a gap and release several buffered payloads.
    pub delivered: Vec<(Sequence, Bytes)>,
    /// True when the arrival was dropped without being delivered or buffered
    /// (a duplicate, already superseded, or beyond the reorder window).
    pub dropped: bool,
    /// True when the arrival was accepted and held awaiting its gap.
    pub buffered: bool,
}

/// Bounded in-order reassembly buffer (spec 11.2, 11.3).
///
/// Enforces the gateway contract: packets are injected into the TUN in
/// `sequence_number` order. Arrivals ahead of the next expected sequence are
/// held until the gap fills; duplicates (or stale/past) arrivals are dropped,
/// first-valid-wins. The buffer is bounded by `capacity` derived from the
/// worst-case RTT delta so a slow path cannot hoard the buffer forever.
pub struct ReorderBuffer {
    dedup: ReorderWindow,
    capacity: usize,
    next_expected: u64,
    buffered: BTreeMap<u64, Bytes>,
}

impl ReorderBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            dedup: ReorderWindow::new(capacity),
            capacity: capacity.max(1),
            next_expected: 0,
            buffered: BTreeMap::new(),
        }
    }

    pub fn pending(&self) -> usize {
        self.buffered.len()
    }

    /// Feeds one inbound (sequence, payload). The returned `delivered` list is
    /// what may be passed upstream, in order.
    pub fn deliver(&mut self, seq: Sequence, payload: Bytes) -> ReorderOutcome {
        if !self.dedup.accept(seq) {
            // Duplicate: first-valid-wins (also covers dups of buffered seqs).
            return ReorderOutcome { dropped: true, ..Default::default() };
        }
        let s = seq.get();
        let far_ahead = s.saturating_sub(self.next_expected) > self.capacity as u64;
        if s < self.next_expected {
            // Past the contiguous head (window wrapped over it): stale.
            return ReorderOutcome { dropped: true, ..Default::default() };
        }
        if far_ahead {
            // Too far ahead to ever assemble in-order inside the window.
            return ReorderOutcome { dropped: true, ..Default::default() };
        }
        if s != self.next_expected {
            if self.buffered.len() >= self.capacity {
                // Window exhausted: drop the newcomer rather than evict nearby
                // buffered packets that are closer to filling the gap.
                return ReorderOutcome { dropped: true, ..Default::default() };
            }
            self.buffered.insert(s, payload);
            return ReorderOutcome { buffered: true, ..Default::default() };
        }

        // Contiguous head: deliver this payload, then drain everything that
        // just became contiguous.
        let mut delivered = vec![(seq, payload)];
        loop {
            self.next_expected = self.next_expected.wrapping_add(1);
            match self.buffered.remove(&self.next_expected) {
                Some(p) => delivered.push((Sequence::new(self.next_expected), p)),
                None => break,
            }
        }
        ReorderOutcome { delivered, ..Default::default() }
    }
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

    #[test]
    fn reorder_buffer_passes_through_in_order() {
        let mut b = ReorderBuffer::new(4);
        let o = b.deliver(Sequence::new(0), Bytes::from_static(b"zero"));
        assert_eq!(o.delivered.len(), 1);
        assert_eq!(o.delivered[0].1, Bytes::from_static(b"zero"));
        let o = b.deliver(Sequence::new(1), Bytes::from_static(b"one"));
        assert_eq!(o.delivered.len(), 1);
        assert!(!o.dropped && !o.buffered);
    }

    #[test]
    fn reorder_buffer_holds_gaps_and_releases_contiguous_chain() {
        let mut b = ReorderBuffer::new(8);
        let o = b.deliver(Sequence::new(4), Bytes::from_static(b"four"));
        assert!(o.buffered, "ahead of head is held");
        assert!(o.delivered.is_empty());
        let o = b.deliver(Sequence::new(0), Bytes::from_static(b"zero"));
        assert_eq!(o.delivered.len(), 1, "only seq0 contiguous yet (1..3 missing)");
        let o = b.deliver(Sequence::new(1), Bytes::from_static(b"one"));
        assert_eq!(o.delivered.len(), 1, "seq1 released, 2..3 still missing");
        let o = b.deliver(Sequence::new(3), Bytes::from_static(b"three"));
        assert!(o.buffered, "seq3 still waiting on seq2");
        let o = b.deliver(Sequence::new(2), Bytes::from_static(b"two"));
        assert_eq!(o.delivered.len(), 3, "seq2 fills the gap, 3 and 4 follow");
        assert_eq!(
            o.delivered
                .iter()
                .map(|(s, _)| s.get())
                .collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn reorder_buffer_rejects_duplicates_of_held_and_delivered() {
        let mut b = ReorderBuffer::new(8);
        assert!(b.deliver(Sequence::new(4), Bytes::from_static(b"four")).buffered);
        let o = b.deliver(Sequence::new(4), Bytes::from_static(b"four-bis"));
        assert!(o.dropped, "duplicate of held seq dropped");
        b.deliver(Sequence::new(0), Bytes::from_static(b"zero"));
        let o = b.deliver(Sequence::new(0), Bytes::from_static(b"zero-bis"));
        assert!(o.dropped, "duplicate of delivered seq dropped");
        assert_eq!(b.pending(), 1);
    }

    #[test]
    fn reorder_buffer_drops_beyond_the_bounded_window() {
        let mut b = ReorderBuffer::new(4);
        b.deliver(Sequence::new(0), Bytes::from_static(b"zero"));
        // next_expected is 1; the 4-wide window reaches seq1..seq5.
        let o = b.deliver(Sequence::new(5), Bytes::from_static(b"five"));
        assert!(!o.dropped && o.buffered, "seq5 is the far edge of the window");
        let o = b.deliver(Sequence::new(6), Bytes::from_static(b"six"));
        assert!(o.dropped, "seq6 is beyond a capacity ahead of the head");
        assert_eq!(o.delivered.len(), 0);
    }

    #[test]
    fn reorder_buffer_bounds_the_window_without_evicting() {
        let mut b = ReorderBuffer::new(4);
        // Head stuck at 0; buffer the widest reachable gap: seq1..4 fill the
        // 4-slot window without releasing anything.
        for s in 1..=4 {
            assert!(
                b.deliver(Sequence::new(s), Bytes::from_static(b"x")).buffered,
                "seq{} held inside the window",
                s
            );
        }
        assert_eq!(b.pending(), 4, "window filled with seq1..4");
        let o = b.deliver(Sequence::new(5), Bytes::from_static(b"five"));
        assert!(o.dropped, "seq5 exceeds the window; never evicts 1..4");
        assert_eq!(b.pending(), 4);
    }
}