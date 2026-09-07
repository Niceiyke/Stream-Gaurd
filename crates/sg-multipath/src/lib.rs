//! Multipath scheduling, failover, redundancy, sequencing, deduplication
//! and reordering (spec section 12).
//!
//! Phase 1: active/standby. Phase 2: adaptive redundancy. Phase 3:
//! weighted bonding. The scheduler is the primary differentiating
//! component and owns authoritative path state.

use std::collections::{BTreeMap, HashMap};

use bytes::Bytes;
use sg_core::{error::Result, PathId, Sequence};
use sg_health::{DefaultScorer, PathMetrics, Scorer};

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
    /// No eligible path right now; the uplink loop should skip this packet.
    Skip,
}

/// Feeds scheduler decisions; the engine submits metric updates as
/// they arrive and the scheduler streams out a latest-decision handle.
pub trait Scheduler: Send + Sync {
    /// Updates the scheduler with the latest per-path metrics.
    fn update_metrics(&mut self, metrics: &PathMetrics, path: u8) -> Result<()>;

    /// Chooses how to exit the next queued packet.
    fn decide(&mut self) -> Decision;

    /// Current phase.
    fn phase(&self) -> SchedulerPhase;
}

/// Phase 3 weighted-bonding scheduler (spec 12 Phase 3).
///
/// Distributes packets across eligible paths in proportion to a per-path
/// weight derived from the health metrics (bandwidth, loss, srtt, jitter —
/// spec 13). Weights are normalized to sum to ~1 over the eligible set and
/// recomputed on every metric update, so the distribution tracks the paths
/// continuously (spec 12 phase 3 "adjust weights continuously"). Paths that
/// are unreachable or whose loss crossed the 20% eligibility cliff
/// (`PathMetrics::is_eligible`) receive zero weight.
///
/// Selection uses a smooth weighted round robin (no randomness): every
/// packet advances each eligible path's accumulator by its normalized
/// weight and picks the largest, subtracting the total weight from the
/// winner. Over a batch the interleave converges to the weight ratio, and a
/// single eligible path is chosen 100% of the time (today's active/standby
/// is the limit case). No hysteresis is needed: weights move continuously
/// with the metrics (spec 14 is about the *active* pick; bonding spreads
/// by definition).
#[derive(Debug, Default)]
pub struct WeightedBondingScheduler {
    /// Last-fed metric snapshot, keyed by path id.
    metrics: HashMap<u8, PathMetrics>,
    /// Normalized weights; sum ~1 over the eligible paths, 0 for others.
    weights: HashMap<u8, f32>,
    /// Smooth-WRR accumulators (persist across `decide` calls so the
    /// interleave stays proportional over time).
    current: HashMap<u8, f32>,
    /// Sum of all normalized weights (=1 while any path is eligible).
    total_weight: f32,
}

impl WeightedBondingScheduler {
    /// Refreshes the metric snapshot from `paths`, using `metrics` where a
    /// path is metered and an eligible-by-default snapshot elsewhere
    /// (unmetered paths are assumed usable until the health engine says
    /// otherwise — matches `choose_path` in the service engine). Recomputes
    /// the normalized weights.
    pub fn update_from(
        &mut self,
        paths: impl Iterator<Item = PathId>,
        metrics: &HashMap<PathId, PathMetrics>,
    ) {
        self.metrics.clear();
        for p in paths {
            let m = match metrics.get(&p) {
                Some(m) => m.clone(),
                None => PathMetrics {
                    reachable: true,
                    ..Default::default()
                },
            };
            self.metrics.insert(p.get(), m);
        }
        self.recompute();
    }

    /// The current normalized per-path weights (sum ~1 over eligible paths).
    /// Empty when no path is eligible.
    pub fn normalized_weights(&self) -> Vec<(u8, f32)> {
        let mut w: Vec<(u8, f32)> = self
            .weights
            .iter()
            .map(|(p, w)| (*p, *w))
            .filter(|(_, w)| *w > 0.0)
            .collect();
        w.sort_by_key(|(p, _)| *p);
        w
    }

    /// Adopts an externally-published normalized weight distribution directly.
    ///
    /// Used by the gateway's phase-3 downlink mirror (spec 12 Phase 3): the
    /// *client* owns the authoritative health snapshot and advertises the
    /// per-path weights; this scheduler mirrors that distribution without
    /// recomputing from its own metrics (the gateway runs no probes). The
    /// adopted vector is re-normalized defensively — the advertisement rides
    /// the public wire — and non-finite/zero/negative entries are dropped.
    /// Smooth-WRR accumulators persist, so the interleave stays continuous
    /// across re-adoptions.
    pub fn adopt_weights(&mut self, weights: impl IntoIterator<Item = (u8, f32)>) {
        self.metrics.clear();
        self.weights.clear();
        let mut total = 0.0f32;
        for (p, w) in weights {
            if w.is_finite() && w > 0.0 {
                self.weights.insert(p, w);
                total += w;
            }
        }
        if total.is_finite() && total > 0.0 {
            for w in self.weights.values_mut() {
                *w /= total;
            }
            self.total_weight = 1.0;
        } else {
            self.total_weight = 0.0;
        }
    }

    /// The preferred (highest-weight) eligible path — the active/downlink
    /// preference. Ties keep the currently active path, falling back to the
    /// lowest path id, so a tie never triggers a spurious `PathSelect`.
    /// Iteration is by ascending path id so equal-weight ties are
    /// deterministic (HashMap order is randomized).
    pub fn preferred_path(&self, current: Option<PathId>) -> Option<PathId> {
        let mut ordered: Vec<(u8, f32)> = self
            .weights
            .iter()
            .map(|(p, w)| (*p, *w))
            .collect();
        ordered.sort_by_key(|(p, _)| *p);
        let mut best: Option<(u8, f32)> = None;
        for (p, w) in ordered {
            if w <= 0.0 {
                continue;
            }
            let better = match best {
                None => true,
                Some((_, bw)) if w > bw => true,
                Some((bp, bw)) => {
                    w == bw
                        && current.is_some_and(|c| c.get() == p)
                        && current.is_some_and(|c| c.get() != bp)
                }
            };
            if better {
                best = Some((p, w));
            }
        }
        best.map(|(p, _)| PathId::new(p))
    }

    /// Smooth weighted round robin over the eligible paths (spec 12 Phase 3
    /// "distribute packets according to path capacity/quality"). Candidates
    /// are visited by ascending path id so first-packet ties are
    /// deterministic (HashMap order is randomized).
    pub fn decide(&mut self) -> Decision {
        let mut eligible: Vec<u8> = self
            .weights
            .iter()
            .filter(|(_, w)| **w > 0.0)
            .map(|(p, _)| *p)
            .collect();
        eligible.sort_unstable();
        if eligible.is_empty() {
            return Decision::Skip;
        }
        let mut best: Option<(u8, f32)> = None;
        for p in eligible {
            let acc = self.current.entry(p).or_insert(0.0);
            *acc += self.weights[&p];
            if best.is_none_or(|(_, bv)| *acc > bv) {
                best = Some((p, *acc));
            }
        }
        match best {
            Some((pid, _)) => {
                if let Some(acc) = self.current.get_mut(&pid) {
                    *acc -= self.total_weight;
                }
                Decision::Send { path: pid }
            }
            None => Decision::Skip,
        }
    }

    /// Recomputes the normalized weights from the stored metric snapshot.
    /// Raw weight mirrors `DefaultScorer` (spec 7 weights: bandwidth 40%,
    /// loss 30%, latency 20%, jitter 10%) so bonding and health scoring
    /// agree; ineligible paths are clamped to zero.
    fn recompute(&mut self) {
        let mut raw: HashMap<u8, f32> = HashMap::new();
        let mut total = 0.0f32;
        for (p, m) in &self.metrics {
            let w = if m.is_eligible() { DefaultScorer::default().score(m) } else { 0.0 };
            raw.insert(*p, w);
            total += w;
        }
        self.weights.clear();
        self.total_weight = 0.0;
        if total > 0.0 {
            for (p, w) in raw {
                let n = w / total;
                self.weights.insert(p, n);
                self.total_weight += n;
            }
        }
    }
}

impl Scheduler for WeightedBondingScheduler {
    fn update_metrics(&mut self, metrics: &PathMetrics, path: u8) -> Result<()> {
        self.metrics.insert(path, metrics.clone());
        self.recompute();
        Ok(())
    }

    fn decide(&mut self) -> Decision {
        WeightedBondingScheduler::decide(self)
    }

    fn phase(&self) -> SchedulerPhase {
        SchedulerPhase::WeightedBonding
    }
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

    // -----------------------------------------------------------------------
    // Phase 3 weighted bonding (spec 12 Phase 3)
    // -----------------------------------------------------------------------

    fn eligible(srtt_ms: u32, loss: f32, available_kbps: u32) -> PathMetrics {
        PathMetrics {
            reachable: true,
            srtt_ms,
            loss,
            available_kbps,
            ..Default::default()
        }
    }

    #[test]
    fn bonding_weights_sum_to_one_over_eligible_paths() {
        let mut sched = WeightedBondingScheduler::default();
        let mut metrics = HashMap::new();
        metrics.insert(PathId::new(1), eligible(20, 0.01, 50_000));
        metrics.insert(PathId::new(2), eligible(100, 0.05, 10_000));
        metrics.insert(PathId::new(3), eligible(200, 0.12, 2_000));
        sched.update_from([PathId::new(1), PathId::new(2), PathId::new(3)].into_iter(), &metrics);

        let w = sched.normalized_weights();
        assert_eq!(w.len(), 3, "all three eligible paths carry weight");
        let sum: f32 = w.iter().map(|(_, w)| w).sum();
        assert!(
            (sum - 1.0).abs() < 1e-4,
            "normalized weights sum to ~1, got {sum}"
        );
        // Weights are monotone with health: path 1 (fast, clean) > path 2 > path 3.
        assert!(w[0].1 > w[1].1 && w[1].1 > w[2].1, "health orders the weights");
    }

    #[test]
    fn bonding_penalizes_srtt_loss_and_jitter() {
        let fast = eligible(20, 0.01, 50_000);
        let slow = eligible(180, 0.01, 50_000);
        let lossy = eligible(20, 0.15, 50_000);
        let jittery = PathMetrics {
            jitter_ms: 40,
            ..eligible(20, 0.01, 50_000)
        };

        let s = DefaultScorer::default();
        assert!(s.score(&fast) > s.score(&slow), "high srtt is penalized");
        assert!(s.score(&fast) > s.score(&lossy), "high loss is penalized");
        assert!(s.score(&fast) > s.score(&jittery), "high jitter is penalized");
    }

    #[test]
    fn bonding_excludes_ineligible_paths_from_the_mix() {
        let mut sched = WeightedBondingScheduler::default();
        let mut metrics = HashMap::new();
        metrics.insert(PathId::new(1), eligible(20, 0.01, 50_000));
        // Path 2: reachable but loss crossed the 20% cliff — ineligible.
        metrics.insert(PathId::new(2), eligible(20, 0.25, 50_000));
        // Path 3: hard-unreachable.
        metrics.insert(PathId::new(3), PathMetrics {
            reachable: false,
            ..Default::default()
        });
        sched.update_from(
            [PathId::new(1), PathId::new(2), PathId::new(3)].into_iter(),
            &metrics,
        );

        let w = sched.normalized_weights();
        assert_eq!(w.len(), 1, "only the one eligible path keeps weight");
        assert!((w[0].1 - 1.0).abs() < 1e-4, "single eligible path gets all weight");
        assert_eq!(
            sched.decide(),
            Decision::Send { path: 1 },
            "the lone eligible path carries every packet"
        );
    }

    #[test]
    fn bonding_weights_move_continuously_when_metrics_update() {
        let mut sched = WeightedBondingScheduler::default();
        let mut metrics = HashMap::new();
        metrics.insert(PathId::new(1), eligible(20, 0.01, 50_000));
        metrics.insert(PathId::new(2), eligible(20, 0.01, 50_000));
        sched.update_from([PathId::new(1), PathId::new(2)].into_iter(), &metrics);
        let w0 = sched.normalized_weights();
        assert!((w0[0].1 - 0.5).abs() < 1e-4, "equal metrics -> equal weights");

        // Path 2 keeps degrading one step at a time; its share must shrink
        // monotonically (spec 12 phase 3 "adjust weights continuously" — no
        // hysteresis step in the weights themselves).
        let mut prev = w0[1].1;
        for (srtt_ms, loss) in [(60, 0.02), (120, 0.05), (180, 0.12)] {
            sched.update_metrics(&eligible(srtt_ms, loss, 50_000), 2).unwrap();
            let w = sched.normalized_weights();
            let w2 = w.iter().find(|(p, _)| *p == 2).map(|(_, w)| *w).unwrap();
            assert!(w2 < prev, "path 2 share keeps shrinking: {prev} -> {w2}");
            prev = w2;
        }
    }

    #[test]
    fn bonding_distributes_proportional_to_weight() {
        let mut sched = WeightedBondingScheduler::default();
        let mut metrics = HashMap::new();
        // Healthy fast path vs. a slower path; raw scores are ~0.968 and
        // ~0.27, so the normalized ratio is roughly 4:1 and definitely > 2:1.
        metrics.insert(PathId::new(1), eligible(20, 0.01, 50_000));
        metrics.insert(PathId::new(2), eligible(160, 0.12, 5_000));
        sched.update_from([PathId::new(1), PathId::new(2)].into_iter(), &metrics);

        let w = sched.normalized_weights();
        assert_eq!(w.len(), 2);
        let strong = w.iter().find(|(p, _)| *p == 1).unwrap().1;
        let weak = w.iter().find(|(p, _)| *p == 2).unwrap().1;
        assert!(strong > weak, "healthy path dominates the weight");

        let mut hits = [0u64; 2];
        for _ in 0..60 {
            match sched.decide() {
                Decision::Send { path: 1 } => hits[0] += 1,
                Decision::Send { path: 2 } => hits[1] += 1,
                other => panic!("unexpected bonding decision {other:?}"),
            }
        }
        assert!(hits[0] > 0 && hits[1] > 0, "both paths receive traffic");
        let ratio = hits[0] as f32 / hits[1] as f32;
        let wanted = strong / weak;
        assert!(
            (ratio - wanted).abs() <= 0.5,
            "empirical ratio {ratio} tracks the weight ratio {wanted}"
        );
    }

    #[test]
    fn bonding_single_path_fallback_uses_it_always() {
        let mut sched = WeightedBondingScheduler::default();
        let mut metrics = HashMap::new();
        metrics.insert(PathId::new(1), eligible(20, 0.01, 50_000));
        sched.update_from([PathId::new(1)].into_iter(), &metrics);

        for _ in 0..20 {
            assert_eq!(
                sched.decide(),
                Decision::Send { path: 1 },
                "only one eligible path: 100% of packets on it"
            );
        }
        assert_eq!(sched.preferred_path(None), Some(PathId::new(1)));
    }

    #[test]
    fn bonding_prefers_the_current_active_path_on_ties() {
        let mut sched = WeightedBondingScheduler::default();
        let mut metrics = HashMap::new();
        metrics.insert(PathId::new(1), eligible(20, 0.01, 50_000));
        metrics.insert(PathId::new(2), eligible(20, 0.01, 50_000));
        sched.update_from([PathId::new(1), PathId::new(2)].into_iter(), &metrics);

        assert_eq!(
            sched.preferred_path(Some(PathId::new(2))),
            Some(PathId::new(2)),
            "an equal-weight tie keeps the current active path (no re-announce)"
        );
        assert_eq!(
            sched.preferred_path(None),
            Some(PathId::new(1)),
            "no current active path: lowest id wins the tie"
        );
    }

    #[test]
    fn bonding_skips_when_no_path_is_eligible() {
        let mut sched = WeightedBondingScheduler::default();
        let mut metrics = HashMap::new();
        metrics.insert(PathId::new(1), PathMetrics {
            reachable: false,
            ..Default::default()
        });
        sched.update_from([PathId::new(1)].into_iter(), &metrics);
        assert!(sched.normalized_weights().is_empty());
        assert_eq!(sched.decide(), Decision::Skip);
        assert_eq!(sched.preferred_path(None), None);
    }

    #[test]
    fn adopted_weights_are_renormalized_and_defensively_filtered() {
        // Gateway downlink mirror: the advertised vector is treated as
        // untrusted input and re-normalized before anything is scheduled.
        let mut sched = WeightedBondingScheduler::default();
        sched.adopt_weights([
            (1, 8.0),   // dominant path
            (2, 2.0),   // minor path
            (3, 0.0),   // zero weight dropped
            (4, -1.0),  // negative weight dropped
            (5, f32::NAN),
            (6, f32::INFINITY),
        ]);

        let w = sched.normalized_weights();
        assert_eq!(w.len(), 2, "only positive finite entries survive adoption");
        let sum: f32 = w.iter().map(|(_, w)| w).sum();
        assert!((sum - 1.0).abs() < 1e-4, "adopted weights are re-normalized");
        assert!((w[0].1 - 0.8).abs() < 1e-4, "path 1 keeps its 4:1 dominance");
        assert!((w[1].1 - 0.2).abs() < 1e-4, "path 2 keeps its 1:4 share");
    }

    #[test]
    fn adopted_weights_distribute_and_survive_re_adoption() {
        // 3:1 adoption across two paths: WRR must hit both and re-adopting
        // the same vector (client re-advertisement cadence) must not disturb
        // the interleave.
        let mut sched = WeightedBondingScheduler::default();
        for _ in 0..3 {
            sched.adopt_weights([(1, 3.0), (2, 1.0)]);
            let mut hits = [0u64; 2];
            for _ in 0..8 {
                match sched.decide() {
                    Decision::Send { path: 1 } => hits[0] += 1,
                    Decision::Send { path: 2 } => hits[1] += 1,
                    other => panic!("unexpected bonding decision {other:?}"),
                }
            }
            assert!(hits[0] > 0 && hits[1] > 0, "both adopted paths receive work");
            assert_eq!(hits[0] + hits[1], 8);
            assert!(
                (hits[0] as f32 / hits[1] as f32 - 3.0).abs() <= 0.5,
                "empirical ratio tracks the adopted 3:1 weights: {:?}",
                hits
            );
        }
    }

    #[test]
    fn adopting_empty_weights_skips_until_new_weights_arrive() {
        let mut sched = WeightedBondingScheduler::default();
        sched.adopt_weights([(1, 1.0)]);
        assert_eq!(sched.decide(), Decision::Send { path: 1 });

        // A stale/empty advertisement must leave nothing schedulable...
        sched.adopt_weights([]);
        assert_eq!(sched.decide(), Decision::Skip);
        assert!(sched.normalized_weights().is_empty());

        // ...until a fresh one re-arms the scheduler.
        sched.adopt_weights([(2, 1.0)]);
        assert_eq!(sched.decide(), Decision::Send { path: 2 });
    }
}