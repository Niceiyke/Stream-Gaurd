//! Per-path health measurement and scoring.
//!
//! Mirrors spec section 13 (Health Engine). The engine must distinguish:
//! link down, Internet unreachable, gateway unreachable, high loss,
//! high latency, bandwidth collapse.

use sg_core::Sequence;

/// Per-path health metrics.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PathMetrics {
    pub reachable: bool,
    /// Instantaneous RTT in milliseconds.
    pub rtt_ms: u32,
    /// Smoothed RTT (EWMA) in milliseconds.
    pub srtt_ms: u32,
    /// Jitter (mean absolute deviation of RTT) in milliseconds.
    pub jitter_ms: u32,
    /// Recent loss ratio in the range 0.0 (none) .. 1.0 (all lost).
    pub loss: f32,
    /// Estimated available upload throughput in kilobits/sec.
    pub available_kbps: u32,
    /// Seconds since the path last changed health state.
    pub stability_secs: u64,
    /// Raw reference to the last probe sequence for telemetry.
    pub last_probe: Option<Sequence>,
}

/// Failure mode classification (spec 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    LinkDown,
    InternetUnreachable,
    GatewayUnreachable,
    HighLoss,
    HighLatency,
    BandwidthCollapse,
}

impl PathMetrics {
    /// True when the path can currently carry protected traffic.
    pub fn is_eligible(&self) -> bool {
        self.reachable && self.loss < 0.20
    }
}

/// Produces a score from `PathMetrics`.
pub trait Scorer: Send + Sync {
    /// Composite score; higher is better. Policy-dependent.
    fn score(&self, metrics: &PathMetrics) -> f32;
}

/// Default weighted scorer (spec 7 initial weights):
/// bandwidth 40%, loss 30%, latency 20%, jitter 10%.
///
/// Threshold-penalty model is intentionally simple for the scaffold and
/// must be replaced by policy-based scoring.
pub struct DefaultScorer {
    pub bandwidth_weight: f32,
    pub loss_weight: f32,
    pub latency_weight: f32,
    pub jitter_weight: f32,
}

impl Default for DefaultScorer {
    fn default() -> Self {
        Self {
            bandwidth_weight: 0.40,
            loss_weight: 0.30,
            latency_weight: 0.20,
            jitter_weight: 0.10,
        }
    }
}

impl Scorer for DefaultScorer {
    fn score(&self, m: &PathMetrics) -> f32 {
        if !m.reachable {
            return 0.0;
        }
        let bw = (m.available_kbps as f32 / 50_000.0).min(1.0); // 50 Mbps reference
        let loss = 1.0 - (m.loss * 4.0).min(1.0);
        let latency = 1.0 - (m.srtt_ms as f32 / 200.0).min(1.0);
        let jitter = 1.0 - (m.jitter_ms as f32 / 50.0).min(1.0);
        self.bandwidth_weight * bw
            + self.loss_weight * loss
            + self.latency_weight * latency
            + self.jitter_weight * jitter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_scores_zero() {
        let m = PathMetrics {
            reachable: false,
            ..Default::default()
        };
        assert_eq!(DefaultScorer::default().score(&m), 0.0);
    }

    #[test]
    fn healthy_beats_lossy() {
        let healthy = PathMetrics {
            srtt_ms: 20,
            loss: 0.01,
            available_kbps: 40_000,
            reachable: true,
            ..Default::default()
        };
        let lossy = PathMetrics {
            srtt_ms: 20,
            loss: 0.10,
            available_kbps: 40_000,
            reachable: true,
            ..Default::default()
        };
        let s = DefaultScorer::default();
        assert!(s.score(&healthy) > s.score(&lossy));
    }
}