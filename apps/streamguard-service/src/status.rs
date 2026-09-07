//! Local status plane (spec 21 "Wordlyte Integration" data list, spec 22
//! authenticated local IPC, engineering step 12 "Desktop status UI").
//!
//! `StatusProvider` is a cloneable handle over the engine's `Shared` state
//! and `Counters`; its `snapshot()` materializes the status data the spec
//! enumerates — protection enabled, active paths, path quality, aggregate
//! bandwidth, current mode and warnings — into a serde-ready
//! `StatusSnapshot` for the IPC server (`crate::ipc`).
//!
//! Mode derivation follows the engine's eligibility rule
//! (`PathMetrics::is_eligible` = reachable && loss < 20%, spec 13): an
//! unmetered path is treated as eligible — exactly how `choose_path` treats
//! a missing entry — so the first snapshot after startup already reports the
//! session as protecting.
//!
//! Lock order: `session → metrics → counters` (never `metrics` while
//! acquiring `session`; see AGENTS.md).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use sg_core::{PathId, SessionId};
use sg_health::PathMetrics;
use tokio::sync::Mutex;

use crate::client::{Counters, Shared};

/// The first 4 bytes of `SessionId` — what crosses the wire (spec 11.1) and
/// what the IPC handshake binds the auth MAC to.
pub fn session_prefix(session_id: SessionId) -> u32 {
    let b = session_id.as_guid().as_bytes();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Current protection mode (spec 21 "current mode").
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Mode {
    /// Fewer than two eligible paths are bound (or none at all).
    SinglePath,
    /// Two or more bound paths with exactly one eligible — the failover
    /// regime of spec 12 phase 1.
    ActiveStandby,
    /// Two or more eligible paths share the load (spec 12 phase 3 bonding).
    Bonding,
}

/// Per-path row of the status table (spec 21 "path quality").
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PathStatus {
    pub path_id: u8,
    pub reachable: bool,
    pub rtt_ms: u32,
    pub srtt_ms: u32,
    pub jitter_ms: u32,
    /// Loss ratio 0.0 ..= 1.0.
    pub loss: f32,
    pub available_kbps: u32,
    pub stability_secs: u64,
}

/// Counters subset exposed in the snapshot (a stable, deterministic view of
/// `Counters` for the UI; `uplink` is a sorted map so the JSON is stable).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StatusCounters {
    pub frames_to_host: u64,
    pub datagrams_to_gateway: u64,
    pub duplicates_dropped: u64,
    pub keepalives: u64,
    pub path_selects: u64,
    pub path_failures: u64,
    pub soft_failures: u64,
    pub probes_sent: u64,
    pub duplicates_sent: u64,
    pub weight_sets: u64,
    pub status_auth_failures: u64,
    /// Per-path primary `Data` envelopes sent (spec 12 phase 3 distribution).
    pub uplink: BTreeMap<u8, u64>,
}

impl From<&Counters> for StatusCounters {
    fn from(c: &Counters) -> Self {
        Self {
            frames_to_host: c.frames_to_host,
            datagrams_to_gateway: c.datagrams_to_gateway,
            duplicates_dropped: c.duplicates_dropped,
            keepalives: c.keepalives,
            path_selects: c.path_selects,
            path_failures: c.path_failures,
            soft_failures: c.soft_failures,
            probes_sent: c.probes_sent,
            duplicates_sent: c.duplicates_sent,
            weight_sets: c.weight_sets,
            status_auth_failures: c.status_auth_failures,
            uplink: c.uplink.iter().map(|(p, n)| (p.get(), *n)).collect(),
        }
    }
}

/// One snapshot of the running engine (spec 21 data list).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StatusSnapshot {
    /// First 4 bytes of the session id (the wire id).
    pub session_prefix: u32,
    /// True while at least one bound path is eligible.
    pub protecting: bool,
    pub mode: Mode,
    /// One row per bound path, sorted by path id.
    pub paths: Vec<PathStatus>,
    /// Sum of `available_kbps` over eligible paths (spec 21 "aggregate
    /// available bandwidth").
    pub aggregate_kbps: u32,
    /// Downlink path the gateway was last (or is being) steered to.
    pub active_path: Option<u8>,
    pub counters: StatusCounters,
    pub warnings: Vec<String>,
}

/// Snapshot source for a `StatusProvider`.
#[derive(Clone)]
enum StatusSource {
    /// Reads the live engine `Shared` state and `Counters` (production).
    Live {
        shared: Arc<Shared>,
        counters: Arc<Mutex<Counters>>,
    },
    /// Answers fixed snapshots from a closure (external harnesses/tests).
    Fixed(Arc<dyn Fn() -> StatusSnapshot + Send + Sync>),
}

/// Cloneable handle the IPC server uses to answer snapshot requests.
///
/// Cheap to clone: the live source shares the same `Arc<Shared>` /
/// `Arc<Mutex<Counters>>` the engine's loops run on, so one provider can be
/// owned by the accept loop and cloned into every connection worker.
#[derive(Clone)]
pub struct StatusProvider {
    source: StatusSource,
}

impl StatusProvider {
    pub(crate) fn new(shared: Arc<Shared>, counters: Arc<Mutex<Counters>>) -> Self {
        Self {
            source: StatusSource::Live { shared, counters },
        }
    }

    /// Builds a provider that answers from a controllable closure instead of
    /// live engine state — lets external harnesses (e.g. the Wordlyte SDK
    /// integration tests) stand up `spawn_status_server` with a fixed
    /// snapshot, including injected warnings or a degraded mode. The closure
    /// must be infallible, cheap and bounded (spec 22.5 worker rules); this
    /// constructor is for tests and sample consumers, never a replacement
    /// for the engine's own `StatusProvider::new`.
    pub fn from_snapshot_fn(f: impl Fn() -> StatusSnapshot + Send + Sync + 'static) -> Self {
        Self {
            source: StatusSource::Fixed(Arc::new(f)),
        }
    }

    /// Materializes the current engine state. Bounded work: one `Session`
    /// lock acquisition, one `metrics` clone and one counters clone (or one
    /// closure call for a fixed provider).
    pub async fn snapshot(&self) -> StatusSnapshot {
        match &self.source {
            StatusSource::Live { shared, counters } => {
                let (session_id, active, path_ids) = {
                    let s = shared.session.lock().await;
                    (
                        s.session_id(),
                        s.active_path(),
                        s.path_ids().collect::<Vec<_>>(),
                    )
                };
                let metrics = {
                    let m = shared.metrics.lock().await;
                    m.clone()
                };
                let counters = counters.lock().await.clone();
                project_snapshot(session_id, active, path_ids, &metrics, &counters)
            }
            StatusSource::Fixed(f) => f(),
        }
    }
}

/// Pure projection of engine state into a snapshot. Kept free of `async` and
/// of any `Shared` plumbing so the mode/eligibility rules are unit-testable
/// with plain data.
fn project_snapshot(
    session_id: SessionId,
    active: Option<PathId>,
    path_ids: Vec<PathId>,
    metrics: &HashMap<PathId, PathMetrics>,
    counters: &Counters,
) -> StatusSnapshot {
    let prefix = session_prefix(session_id);
    let mut paths = Vec::with_capacity(path_ids.len());
    let mut ordered = path_ids;
    ordered.sort_by_key(|p| p.get());

    let mut eligible = 0usize;
    let mut aggregate_kbps = 0u32;
    let mut warnings: Vec<String> = Vec::new();

    for pid in ordered {
        let m = metrics.get(&pid);
        // An unmetered path is eligible by default (engine `choose_path`).
        let is_eligible = m.map(|m| m.is_eligible()).unwrap_or(true);
        if is_eligible {
            eligible += 1;
            aggregate_kbps = aggregate_kbps.saturating_add(m.map(|m| m.available_kbps).unwrap_or(0));
        } else if let Some(m) = m {
            warnings.push(format!(
                "path {} degraded: loss {:.0}%",
                pid.get(),
                m.loss * 100.0
            ));
        }
        let (reachable, rtt_ms, srtt_ms, jitter_ms, loss, available_kbps, stability_secs) =
            match m {
                Some(m) => (
                    m.reachable,
                    m.rtt_ms,
                    m.srtt_ms,
                    m.jitter_ms,
                    m.loss,
                    m.available_kbps,
                    m.stability_secs,
                ),
                None => (true, 0, 0, 0, 0.0, 0, 0),
            };
        paths.push(PathStatus {
            path_id: pid.get(),
            reachable,
            rtt_ms,
            srtt_ms,
            jitter_ms,
            loss,
            available_kbps,
            stability_secs,
        });
    }

    // Spec 21 "current mode" from eligibility (successor of the phase-1
    // active/standby and phase-3 bonding regimes).
    let mode = match eligible {
        0 => {
            warnings.push("no eligible path: protection is degraded".to_string());
            Mode::SinglePath
        }
        1 => Mode::ActiveStandby,
        _ => Mode::Bonding,
    };

    StatusSnapshot {
        session_prefix: prefix,
        protecting: eligible > 0,
        mode,
        paths,
        aggregate_kbps,
        active_path: active.map(|p| p.get()),
        counters: StatusCounters::from(counters),
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sg_session::session_id_from_wire;

    #[test]
    fn session_prefix_is_the_wire_prefix() {
        let id = session_id_from_wire(0x12345678);
        assert_eq!(session_prefix(id), 0x12345678);
    }

    /// Two healthy paths → Bonding; aggregate and per-path rows carry the
    /// injected metrics; protecting is on.
    #[test]
    fn two_eligible_paths_project_to_bonding() {
        let prefix = 0xdead_beef;
        let mut metrics = HashMap::new();
        metrics.insert(
            PathId::new(1),
            PathMetrics {
                reachable: true,
                rtt_ms: 25,
                srtt_ms: 20,
                jitter_ms: 3,
                loss: 0.01,
                available_kbps: 50_000,
                stability_secs: 12,
                ..Default::default()
            },
        );
        metrics.insert(
            PathId::new(2),
            PathMetrics {
                reachable: true,
                srtt_ms: 90,
                loss: 0.10,
                available_kbps: 4_000,
                ..Default::default()
            },
        );
        let snap = project_snapshot(
            session_id_from_wire(prefix),
            Some(PathId::new(1)),
            vec![PathId::new(2), PathId::new(1)],
            &metrics,
            &Counters::default(),
        );
        assert_eq!(snap.session_prefix, prefix);
        assert!(snap.protecting);
        assert_eq!(snap.mode, Mode::Bonding);
        assert_eq!(snap.paths.len(), 2);
        assert_eq!(snap.paths[0].path_id, 1, "rows sorted by path id");
        assert_eq!(snap.paths[0].srtt_ms, 20);
        assert_eq!(snap.paths[1].path_id, 2);
        assert_eq!(
            snap.aggregate_kbps,
            54_000,
            "aggregate sums the eligible paths' capacity"
        );
        assert_eq!(snap.active_path, Some(1));
        assert!(snap.warnings.is_empty());
    }

    /// Exactly one losing-but-reachable path → ActiveStandby; a fully clean
    /// set with a 20%+ loss on the second path is a warning candidate.
    #[test]
    fn a_single_eligible_path_is_active_standby() {
        let mut metrics = HashMap::new();
        metrics.insert(
            PathId::new(1),
            PathMetrics {
                reachable: true,
                srtt_ms: 20,
                loss: 0.01,
                available_kbps: 50_000,
                ..Default::default()
            },
        );
        metrics.insert(
            PathId::new(2),
            PathMetrics {
                reachable: true,
                srtt_ms: 90,
                loss: 0.50, // crosses the 20% eligibility cliff
                available_kbps: 8_000,
                ..Default::default()
            },
        );
        let snap = project_snapshot(
            session_id_from_wire(0x0000_0001),
            Some(PathId::new(1)),
            vec![PathId::new(1), PathId::new(2)],
            &metrics,
            &Counters::default(),
        );
        assert!(snap.protecting, "one eligible path still protects traffic");
        assert_eq!(snap.mode, Mode::ActiveStandby);
        assert_eq!(snap.aggregate_kbps, 50_000, "ineligible capacity excluded");
        assert!(
            snap.warnings
                .iter()
                .any(|w| w.contains("degraded") && w.contains("50%")),
            "the ineligible path surfaces a warning: {snap:?}"
        );
    }

    /// Zero eligible paths → SinglePath + degraded warning + protecting off.
    #[test]
    fn no_eligible_path_is_single_path_with_warning() {
        let mut metrics = HashMap::new();
        metrics.insert(
            PathId::new(1),
            PathMetrics {
                reachable: false, // hard-down path
                ..Default::default()
            },
        );
        let snap = project_snapshot(
            session_id_from_wire(0x0000_0002),
            Some(PathId::new(1)),
            vec![PathId::new(1)],
            &metrics,
            &Counters::default(),
        );
        assert!(!snap.protecting);
        assert_eq!(snap.mode, Mode::SinglePath);
        assert!(
            snap.warnings
                .iter()
                .any(|w| w.contains("no eligible path")),
            "degraded mode is surfaced as a warning"
        );
    }

    /// Unmetered paths are eligible-by-default: a brand-new session already
    /// protects (matches engine `choose_path` for `None` entries).
    #[test]
    fn unmetered_paths_are_eligible_like_the_engine_believes() {
        let snap = project_snapshot(
            session_id_from_wire(0x0000_0003),
            Some(PathId::new(2)),
            vec![PathId::new(1), PathId::new(2)],
            &HashMap::new(),
            &Counters::default(),
        );
        assert!(snap.protecting);
        assert_eq!(snap.mode, Mode::Bonding);
        assert_eq!(snap.aggregate_kbps, 0, "no measurements yet");
        assert!(snap.paths.iter().all(|p| p.reachable));
    }

    /// The counters subset round-trips a populated `Counters` faithfully.
    #[test]
    fn counters_subset_projects_and_round_trips() {
        let c = Counters {
            frames_to_host: 3,
            datagrams_to_gateway: 5,
            weight_sets: 1,
            status_auth_failures: 2,
            ..Default::default()
        };
        let mut c = c;
        c.uplink.insert(PathId::new(2), 2);
        c.uplink.insert(PathId::new(1), 3);

        let sub = StatusCounters::from(&c);
        assert_eq!(sub.frames_to_host, 3);
        assert_eq!(sub.datagrams_to_gateway, 5);
        assert_eq!(sub.weight_sets, 1);
        assert_eq!(sub.status_auth_failures, 2);
        assert_eq!(sub.uplink.len(), 2);

        let json = serde_json::to_string(&sub).unwrap();
        let back: StatusCounters = serde_json::from_str(&json).unwrap();
        assert_eq!(sub, back, "JSON wire round-trip is lossless");
    }
}