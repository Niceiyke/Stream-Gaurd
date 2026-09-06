//! Client tunnel engine (spec 22 service core / engineering step 6).
//!
//! Orchestrates the pieces the service owns:
//!
//! - one `Session` (the device's logical tunnel) holding every path,
//! - one QUIC `PathTransport` per physical path, bound to that session,
//! - a **downlink reader** per path: `recv()` an envelope, dedup via the
//!   per-session reorder window, write the host IP packet into the TUN,
//! - an **uplink task**: read a local packet from the TUN, sequence it,
//!   pick the healthiest eligible path (phase 1 active/standby driven by
//!   `DefaultScorer`) and send it,
//! - a **keepalive task per path**: emit `Keepalive` envelopes on every
//!   bound path (spec 12 phase 1 "keep alternate path alive") so standby
//!   QUIC connections stay warm and their NAT mappings stay fresh for
//!   failover (spec 17 stable egress),
//! - **rev1 path control**: when the health-driven pick changes, the uplink
//!   task sends a `Control::PathSelect` so the gateway moves that session's
//!   downlink to the newly active path,
//! - **failover**: a transport-level failure (reader `recv` error or a failed
//!   keepalive send) marks the path unreachable and immediately promotes the
//!   healthiest surviving path, steering the gateway's downlink there too
//!   (spec 31.4 path failure).
//!
//! The host-side TUN is generic: `LoopbackTun` (non-blocking `WouldBlock`)
//! is used by the tests; real platform adapters block and must be driven
//! on a dedicated OS thread (spec 22.5).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use sg_core::error::Error;
use sg_core::{PathId, SessionId};
use sg_health::{DefaultScorer, PathMetrics, Scorer};
use sg_protocol::control::ControlMsg;
use sg_protocol::{Envelope, PacketType, VERSION};
use sg_session::Session;
use sg_transport::quic::{bootstrap_v1, connect_path};
use sg_transport::PathTransport;
use sg_tun::Tun;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

/// Shared bundle of state every task needs.
struct Shared {
    session: Mutex<Session>,
    metrics: Mutex<HashMap<PathId, PathMetrics>>,
    /// The last active path the gateway was told about (downlink target).
    /// `None` before the first uplink decision.
    notified: Mutex<Option<PathId>>,
    /// Outstanding health probes: (path, probe id) -> sent time; resolved by
    /// the downlink reader when the gateway's `PathStatus` reply arrives.
    pending_probes: Mutex<HashMap<(PathId, u32), std::time::Instant>>,
    /// Consecutive probes lost on each path; crossing the failure threshold
    /// marks the path unreachable — soft failure (spec 12 / 13 / 31.3).
    probe_misses: Mutex<HashMap<PathId, u32>>,
    /// Loss threshold above which the uplink duplicates a packet onto a
    /// redundant path (phase 2 adaptive redundancy, spec 12).
    redundancy_loss_threshold: f32,
}

/// Aggregate counters exposed to tests after the engine runs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counters {
    pub paths: u64,
    /// IP packets written into the local TUN by downlink readers.
    pub frames_to_host: u64,
    /// Uplink data envelopes sent to the gateway.
    pub datagrams_to_gateway: u64,
    /// Sequences rejected by the downlink reorder window.
    pub duplicates_dropped: u64,
    /// Keepalive envelopes emitted on all bound paths (NAT refresh).
    pub keepalives: u64,
    /// `Control::PathSelect` messages sent when the active path changed.
    pub path_selects: u64,
    /// Paths marked unreachable after their transport failed (connection
    /// loss or a keepalive send error), triggering failover.
    pub path_failures: u64,
    /// Paths marked unreachable by the soft-liveness monitor (no inbound
    /// envelope within `probe_timeout`), then failed over.
    pub soft_failures: u64,
/// Per-path health probes sent (each awaits a `PathStatus` reply).
    pub probes_sent: u64,
    /// Uplink `Duplicate` copies sent when the selected path was degraded
    /// (phase 2 adaptive redundancy, spec 12).
    pub duplicates_sent: u64,
}

/// A running client engine. Call `stop` to tear it down.
pub struct ClientHandle<T: Tun + Send + 'static> {
    run: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
    shared: Arc<Shared>,
    /// Exposed so tests can `enqueue` replies into the TUN and
    /// `drain_outbound` to assert that decrypted downlink packets arrived.
    pub tun: Arc<Mutex<T>>,
    pub counters: Arc<Mutex<Counters>>,
}

impl<T: Tun + Send + 'static> ClientHandle<T> {
    /// Gracefully shuts down the uplink and downlink loops.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(run) = self.run.take() {
            let _ = run.await;
        }
    }

    pub async fn counters(&self) -> Counters {
        self.counters.lock().await.clone()
    }

    /// Updates the health snapshot for `path_id` so the uplink loop can
    /// re-rank paths (phase 1 active/standby selection).
    pub async fn set_metrics(&self, path_id: PathId, metrics: PathMetrics) {
        self.shared.metrics.lock().await.insert(path_id, metrics);
    }

    /// The path the uplink currently selects (highest-scoring eligible).
    pub async fn active_path(&self) -> Option<PathId> {
        self.shared.session.lock().await.active_path()
    }

    /// The health engine's current snapshot for `path_id` (probe-derived RTT,
    /// loss and reachability). `None` while the path is still unmetered.
    pub async fn path_metrics(&self, path_id: PathId) -> Option<PathMetrics> {
        self.shared.metrics.lock().await.get(&path_id).cloned()
    }

    /// Force-severs `path_id`'s transport (test hook; simulated physical
    /// path loss). The connection close is detected by the path's reader,
    /// which marks the path unreachable and fails over.
    pub async fn sever_path(&self, path_id: PathId) -> bool {
        let transport = self.shared.session.lock().await.path(path_id).cloned();
        match transport {
            Some(t) => {
                t.close();
                true
            }
            None => false,
        }
    }
}

/// Transport + tuning options consumed by `start`.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Gateway UDP/QUIC endpoint.
    pub addr: std::net::SocketAddr,
    /// TLS SNI / certificate name expected from the gateway.
    pub server_name: String,
    /// Trusted-client QUIC configuration.
    pub client_config: quinn::ClientConfig,
    /// Cadence for app-level `Keepalive` envelopes on every bound path
    /// (NAT-mapping refresh for standby paths, spec 12/17). `Duration::ZERO`
    /// disables keepalives.
    pub keepalive_interval: Duration,
    /// Cadence for per-path health probes fed to the health engine
    /// (spec 31.3 steady state "1 Hz health probes per path"). `Duration::ZERO`
    /// disables probing. Defaults to 1 second.
    pub probe_interval: Duration,
    /// A probe that has not been answered within this window is counted lost.
    /// Defaults to 1 second.
    pub probe_timeout: Duration,
    /// Consecutive lost probes before a path is declared unreachable (soft
    /// failure) and failed over. Defaults to 2.
    pub probe_failure_threshold: u32,
    /// Loss estimate at or above which a selected path is considered
    /// degraded and its packets are duplicated (phase 2 adaptive redundancy,
    /// spec 12): `Decision::Duplicate` sends a `Duplicate` copy of the same
    /// sequence on a second healthy path, and the gateway's reorder window
    /// keeps the first copy. `0.0` disables duplication. Defaults to 0.10.
    pub redundancy_loss_threshold: f32,
}

/// Opens one QUIC path to the gateway per entry, authenticates each with the
/// v1 bootstrap handshake (`token` = gateway-signed session ticket), binds
/// the accredited paths to the session, then starts the uplink + downlink
/// loops and one keepalive task per path.
pub async fn start<T: Tun + Send + 'static>(
    tun: T,
    options: ClientOptions,
    session_id: SessionId,
    paths: &[PathId],
    token: &str,
) -> anyhow::Result<ClientHandle<T>> {
    let tun: Arc<Mutex<T>> = Arc::new(Mutex::new(tun));
    let counters = Arc::new(Mutex::new(Counters::default()));

    let mut session = Session::new(session_id);
    let mut transports = Vec::new();

    // Open and bind one transport per path, in the given order. The first
    // bound path becomes the initial active path; health re-ranks later.
    for path_id in paths.iter().copied() {
        let path = connect_path(
            options.addr,
            &options.server_name,
            options.client_config.clone(),
            path_id,
        )
        .await?;
        // Each path must present the signed session ticket before it can
        // carry traffic for this session (spec 15.5 / engineering step 8).
        let accredited = bootstrap_v1(&path, session_id, token).await?;
        if accredited != session_id {
            anyhow::bail!("gateway accredited a different session ({accredited:?})");
        }
        let path: Arc<dyn PathTransport> = Arc::new(path);
        transports.push((path_id, path.clone()));
        session.add_path(path, path_id)?;
    }

    let initial_active = session.active_path();
    let shared = Arc::new(Shared {
        session: Mutex::new(session),
        metrics: Mutex::new(HashMap::new()),
        notified: Mutex::new(initial_active),
        pending_probes: Mutex::new(HashMap::new()),
        probe_misses: Mutex::new(HashMap::new()),
        redundancy_loss_threshold: options.redundancy_loss_threshold,
    });

    // Spawn one downlink reader per bound path, one keepalive task if a
    // cadence was requested, and one probe task per path if probing is on.
    let mut reader_handles = Vec::new();
    let mut keepalive_handles = Vec::new();
    let mut probe_handles = Vec::new();
    for (path_id, transport) in transports {
        reader_handles.push(tokio::spawn(reader_loop(
            transport.clone(),
            path_id,
            tun.clone(),
            shared.clone(),
            counters.clone(),
        )));
        if !options.keepalive_interval.is_zero() {
            keepalive_handles.push(tokio::spawn(keepalive_loop(
                transport.clone(),
                path_id,
                session_id,
                options.keepalive_interval,
                counters.clone(),
                shared.clone(),
            )));
        }
        if !options.probe_interval.is_zero() {
            probe_handles.push(tokio::spawn(probe_loop(
                transport,
                path_id,
                session_id,
                options.probe_interval,
                options.probe_timeout,
                options.probe_failure_threshold,
                counters.clone(),
                shared.clone(),
            )));
        }
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let run = tokio::spawn(run_loop(
        tun.clone(),
        shared.clone(),
        counters.clone(),
        shutdown_rx,
        reader_handles,
        keepalive_handles,
        probe_handles,
    ));

    Ok(ClientHandle {
        run: Some(run),
        shutdown: Some(shutdown_tx),
        shared,
        tun,
        counters,
    })
}

async fn run_loop<T: Tun + Send + 'static>(
    tun: Arc<Mutex<T>>,
    shared: Arc<Shared>,
    counters: Arc<Mutex<Counters>>,
    mut shutdown: oneshot::Receiver<()>,
    reader_handles: Vec<JoinHandle<()>>,
    keepalive_handles: Vec<JoinHandle<()>>,
    probe_handles: Vec<JoinHandle<()>>,
) {
    let mut uplink_task = tokio::spawn(uplink_loop(tun, shared.clone(), counters));
    tokio::select! {
        _ = &mut shutdown => {}
        res = &mut uplink_task => { if let Err(e) = res { tracing::warn!(error = %e, "uplink loop exited"); } }
    }
    uplink_task.abort();
    for h in reader_handles
        .into_iter()
        .chain(keepalive_handles)
        .chain(probe_handles)
    {
        h.abort();
    }
}

// ---------------------------------------------------------------------------
// Downlink reader – one task per path
// ---------------------------------------------------------------------------

async fn reader_loop<T: Tun + Send + 'static>(
    transport: Arc<dyn PathTransport>,
    path_id: PathId,
    tun: Arc<Mutex<T>>,
    shared: Arc<Shared>,
    counters: Arc<Mutex<Counters>>,
) {
    loop {
        let envelope = match transport.recv().await {
            Ok(e) => e,
            Err(_) => {
                // Transport-level error = hard down signal: fail over now
                // rather than leaving a dead path on the health table.
                fail_path(shared.clone(), counters.clone(), path_id, false).await;
                break;
            }
        };
match envelope.packet_type {
            // Dedup + reorder against the shared per-session window, then
            // inject any payloads that became in-order (spec 11.2).
            PacketType::Data | PacketType::Duplicate => {
                if envelope.packet_type == PacketType::Duplicate {
                    counters.lock().await.duplicates_dropped += 1;
                    continue;
                }
                let outcome = {
                    let mut sess = shared.session.lock().await;
                    sess.enqueue_incoming(envelope.sequence, envelope.payload.clone())
                };
                if outcome.dropped {
                    counters.lock().await.duplicates_dropped += 1;
                }
                for (_, payload) in outcome.delivered {
                    counters.lock().await.frames_to_host += 1;
                    let mut t = tun.lock().await;
                    let _ = t.write(&payload);
                }
            }
            // A probe reply is a clean RTT observation for this path: resolve the
            // outstanding probe, feed the health engine and clear the
            // consecutive-misses counter (soft liveness restored).
            PacketType::PathStatus => {
                let probe_id = probe_id_from_payload(&envelope.payload);
                let sent_at = {
                    let mut pending = shared.pending_probes.lock().await;
                    match probe_id {
                        Some(id) => pending.remove(&(path_id, id)),
                        None => None,
                    }
                };
                {
                    let mut misses = shared.probe_misses.lock().await;
                    misses.insert(path_id, 0);
                }
                if let Some(sent_at) = sent_at {
                    let rtt = probe_rtt_ms(&sent_at);
                    let mut m = shared.metrics.lock().await;
                    m.entry(path_id).or_default().record_probe(Some(rtt));
                }
            }
            // Control / Keepalive / Probe are handled by the holding logic in
            // other milestones (none inbound, or replies we don't act on).
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Keepalive task – one per path; keeps standby paths + NAT mappings alive
// ---------------------------------------------------------------------------

/// Emits an app-level `Keepalive` envelope on `path_id` every `interval`.
///
/// Standby (non-active) paths otherwise carry no traffic; without outbound
/// packets the client's NAT mapping for that path can time out and the
/// gateway egress becomes unreachable exactly when failover needs it
/// (spec 12 phase 1 / spec 17). Sequence 0 is used so keepalives never
/// consume data sequence numbers or pollute the gateway reorder window.
async fn keepalive_loop(
    transport: Arc<dyn PathTransport>,
    path_id: PathId,
    session_id: SessionId,
    interval: Duration,
    counters: Arc<Mutex<Counters>>,
    shared: Arc<Shared>,
) {
    loop {
        tokio::time::sleep(interval).await;
        let env = Envelope {
            version: VERSION,
            packet_type: PacketType::Keepalive,
            flags: 0,
            path_id,
            session_id,
            sequence: sg_core::Sequence::new(0),
            timestamp_ms: 0,
            payload: Bytes::new(),
        };
        if transport.send(env).await.is_err() {
            // The path cannot carry keepalives anymore: treat the send
            // failure as the down signal and let the failover machinery run.
            fail_path(shared.clone(), counters.clone(), path_id, false).await;
            return;
        }
        counters.lock().await.keepalives += 1;
    }
}

// ---------------------------------------------------------------------------
// Path failure + path control (rev1)
// ---------------------------------------------------------------------------

/// Rev1 path control: tells the gateway the session's downlink now uses
/// `path_id` (fire-and-forget datagram). Idempotent via `Shared.notified`:
/// returns true only when the announcement is genuinely new.
async fn announce_path(
    shared: &Arc<Shared>,
    counters: &Arc<Mutex<Counters>>,
    path_id: PathId,
    session_id: SessionId,
) -> bool {
    let changed = {
        let mut notified = shared.notified.lock().await;
        if *notified != Some(path_id) {
            *notified = Some(path_id);
            true
        } else {
            false
        }
    };
    if !changed {
        return false;
    }
    let ctrl = Envelope {
        version: VERSION,
        packet_type: PacketType::Control,
        flags: 0,
        path_id,
        session_id,
        sequence: sg_core::Sequence::new(0),
        timestamp_ms: 0,
        payload: ControlMsg::PathSelect { path: path_id.get() }
            .encode()
            .expect("path select never exceeds u16::MAX"),
    };
    if shared
        .session
        .lock()
        .await
        .send_on(path_id, ctrl)
        .await
        .is_ok()
    {
        counters.lock().await.path_selects += 1;
        true
    } else {
        false
    }
}

/// Marks `dead` unreachable and triggers failover (spec 31.4).
///
/// A transport-level failure (connection loss on `recv`, or a failed
/// keepalive send) is the *hard* down signal; a path that stops answering
/// probes within `probe_timeout` is the *soft* one. Either way the path is
/// made ineligible so `choose_path` never picks it again, and if it was the
/// active path the healthiest surviving path is promoted and the gateway
/// is steered there immediately — downlink resumes on the standby even
/// before the next uplink packet.
async fn fail_path(shared: Arc<Shared>, counters: Arc<Mutex<Counters>>, dead: PathId, soft: bool) {
    {
        let metrics = shared.metrics.lock().await;
        if metrics.get(&dead).is_some_and(|m| !m.reachable) {
            return;
        }
    }
    {
        let mut metrics = shared.metrics.lock().await;
        let entry = metrics.entry(dead).or_default();
        *entry = PathMetrics {
            reachable: false,
            ..Default::default()
        };
    }
    {
        let mut c = counters.lock().await;
        if soft {
            c.soft_failures += 1;
        } else {
            c.path_failures += 1;
        }
    }

    let promotion = {
        let mut sess = shared.session.lock().await;
        let prev = sess.active_path();
        let metrics = shared.metrics.lock().await;
        let best = choose_path(&metrics, sess.path_ids().collect::<Vec<_>>().as_slice(), prev);
        if let Some(b) = best {
            let _ = sess.set_active_path(b);
        }
        // Only steer the gateway when the active path actually moved.
        match (prev, best) {
            (Some(p), Some(b)) if p != b => Some(b),
            _ => None,
        }
    };
    if let Some(next) = promotion {
        let sid = shared.session.lock().await.session_id();
        announce_path(&shared, &counters, next, sid).await;
    }
}

// ---------------------------------------------------------------------------
// Health probe task – one per path; feeds the health engine + soft expiry
// ---------------------------------------------------------------------------

/// Emits a per-path health probe (spec 31.3) and drives the soft-failure
/// arbiter: a probe that is not answered within `probe_timeout` counts as
/// lost (ramping the loss estimate), and `probe_failure_threshold`
/// consecutive lost probes declare the path unreachable (spec 12 phase 1
/// "migrate on failure"). `choose_path` then promotes the healthy standby
/// and `announce_path` moves the gateway's downlink.
#[allow(clippy::too_many_arguments)]
async fn probe_loop(
    transport: Arc<dyn PathTransport>,
    path_id: PathId,
    session_id: SessionId,
    interval: Duration,
    timeout: Duration,
    failure_threshold: u32,
    counters: Arc<Mutex<Counters>>,
    shared: Arc<Shared>,
) {
    let mut next_id: u32 = 0;
    loop {
        tokio::time::sleep(interval).await;
        let id = next_id;
        next_id = next_id.wrapping_add(1);
        shared
            .pending_probes
            .lock()
            .await
            .insert((path_id, id), std::time::Instant::now());
        let env = Envelope {
            version: VERSION,
            packet_type: PacketType::Probe,
            flags: 0,
            path_id,
            session_id,
            sequence: sg_core::Sequence::new(0),
            timestamp_ms: 0,
            payload: Bytes::copy_from_slice(&id.to_be_bytes()),
        };
        if transport.send(env).await.is_err() {
            // The path cannot even carry probes: hard failure.
            fail_path(shared.clone(), counters.clone(), path_id, false).await;
            return;
        }
        counters.lock().await.probes_sent += 1;

        // Count unanswered probes older than the window as lost.
        let (lost, total_misses) = {
            let mut pending = shared.pending_probes.lock().await;
            let now = std::time::Instant::now();
            let lost: Vec<u32> = pending
                .iter()
                .filter(|((pid, _), sent)| {
                    *pid == path_id && now.saturating_duration_since(**sent) >= timeout
                })
                .map(|((_, id), _)| *id)
                .collect();
            for id in &lost {
                pending.remove(&(path_id, *id));
            }
            let lost = lost.len() as u32;
            let mut misses = shared.probe_misses.lock().await;
            let m = misses.entry(path_id).or_insert(0);
            *m = m.saturating_add(lost);
            (lost, *m)
        };
        if lost > 0 {
            let mut m = shared.metrics.lock().await;
            // A fresh entry must start reachable: an unmetered path is assumed
            // usable, and only `fail_path` may flip a path to unreachable.
            // `record_probe(None)` ramps loss; it does not (by itself) mark
            // the path down (spec 13 — the soft-failure trigger is ours).
            let entry = m
                .entry(path_id)
                .or_insert(PathMetrics {
                    reachable: true,
                    ..Default::default()
                });
            for _ in 0..lost {
                entry.record_probe(None);
            }
        }
        if failure_threshold > 0 && total_misses >= failure_threshold {
            shared.probe_misses.lock().await.remove(&path_id);
            fail_path(shared.clone(), counters.clone(), path_id, true).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Uplink loop – local packets into the tunnel
// ---------------------------------------------------------------------------

async fn uplink_loop<T: Tun + Send + 'static>(
    tun: Arc<Mutex<T>>,
    shared: Arc<Shared>,
    counters: Arc<Mutex<Counters>>,
) {
    let mut buf = vec![0u8; 1300];
    loop {
        // Non-blocking read (LoopbackTun returns WouldBlock when idle).
        let n = loop {
            let n = {
                let mut t = tun.lock().await;
                match t.read(&mut buf) {
                    Ok(n) => Ok(n),
                    Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => Err(true),
                    Err(_) => Err(false),
                }
            };
            match n {
                Ok(n) => break n,
                Err(true) => {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    continue;
                }
                Err(false) => return,
            }
        };

        // Sequence + pick the healthiest eligible path, then send. If the
        // selected path is degraded (loss >= redundancy threshold, phase 2
        // adaptive redundancy, spec 12), a `Duplicate` copy of the same
        // sequence also goes out on a second healthy path; the gateway reorder
        // window keeps the first copy to arrive (first-valid-wins).
        let (seq, path_id, session_id) = {
            let mut sess = shared.session.lock().await;
            let seq = sess.next_sequence();
            let best = {
                let metrics = shared.metrics.lock().await;
                let current = sess.active_path();
                choose_path(&metrics, sess.path_ids().collect::<Vec<_>>().as_slice(), current)
            };
            let best = match best {
                Some(p) => p,
                None => continue,
            };
            let _ = sess.set_active_path(best);
            (seq, best, sess.session_id())
        };

        // Rev1 path control: tell the gateway when the active path changes so
        // its downlink follows the failover (fire-and-forget datagram).
        announce_path(&shared, &counters, path_id, session_id).await;

        let env = Envelope {
            version: VERSION,
            packet_type: PacketType::Data,
            flags: 0,
            path_id,
            session_id,
            sequence: seq,
            timestamp_ms: 0,
            payload: Bytes::copy_from_slice(&buf[..n]),
        };
        let _ = shared
            .session
            .lock()
            .await
            .send_on(path_id, env)
            .await;
        counters.lock().await.datagrams_to_gateway += 1;

        // Redundant copy: pick the best *other* healthy path and mirror the
        // same sequence as a `Duplicate` so a lossy active path does not cost
        // us the packet (spec 12 adaptive redundancy). Acquisition order
        // honours the session→metrics convention: never hold one while taking
        // the other.
        let degraded = {
            let metrics = shared.metrics.lock().await;
            metrics.get(&path_id).is_some_and(|m| m.loss >= shared.redundancy_loss_threshold)
                && shared.redundancy_loss_threshold != 0.0
        };
        if degraded {
            let alt = {
                let sess = shared.session.lock().await;
                let metrics = shared.metrics.lock().await;
                let mut ordered: Vec<PathId> =
                    sess.path_ids().filter(|p| *p != path_id).collect();
                ordered.sort_by_key(|p| p.get());
                ordered.into_iter().find(|p| {
                    metrics.get(p).is_some_and(|m| m.is_eligible())
                })
            };
            if let Some(alt) = alt {
                let dup = Envelope {
                    version: VERSION,
                    packet_type: PacketType::Duplicate,
                    flags: 0,
                    path_id: alt,
                    session_id,
                    sequence: seq,
                    timestamp_ms: 0,
                    payload: Bytes::copy_from_slice(&buf[..n]),
};
                let _ = shared.session.lock().await.send_on(alt, dup).await;
                counters.lock().await.datagrams_to_gateway += 1;
                counters.lock().await.duplicates_sent += 1;
            }
        }
    }
}

/// The probe id the client put in the probe and expects echoed back in the
/// `PathStatus` reply (payload is exactly the 4-byte id on both legs).
fn probe_id_from_payload(payload: &[u8]) -> Option<u32> {
    if payload.len() != 4 {
        return None;
    }
    let b: [u8; 4] = payload.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}

/// RTT of a probe reply in milliseconds, from the sent timestamp (the
/// `PathStatus` echoes the probe a moment after it was recorded as pending,
/// so elapsed on the wire is a fair loopback approximation).
fn probe_rtt_ms(sent: &std::time::Instant) -> u32 {
    sent.elapsed().as_millis().min(u32::MAX as u128) as u32
}

/// Picks the eligible path with the highest score among `paths`; an
/// unmetered path is assumed eligible (initial active/standby phase).
/// Ineligible (e.g. unreachable) paths are never chosen.
///
/// Ties (common before the first measurements arrive) are broken toward the
/// currently active path, falling back to the lowest path id, so the initial
/// uplink decision is deterministic and never triggers a spurious
/// `PathSelect`.
fn choose_path(
    metrics: &HashMap<PathId, PathMetrics>,
    paths: &[PathId],
    current: Option<PathId>,
) -> Option<PathId> {
    let scorer = DefaultScorer::default();
    let mut ordered: Vec<PathId> = paths.to_vec();
    ordered.sort_by_key(|p| p.get());
    let mut best: Option<(PathId, f32)> = None;
    for pid in ordered {
        let score = match metrics.get(&pid) {
            Some(m) if m.is_eligible() => scorer.score(m),
            Some(_) => -1.0, // metered but ineligible
            None => 0.0,     // no measurement yet → eligible-by-default
        };
        let better = match best {
            None => true,
            Some((_, best_score)) if score > best_score => true,
            Some((best_pid, best_score)) => {
                // Equal score: if the candidate IS the current active path
                // and the current best is a different path, keep the active
                // one so we never re-announce on a tie.
                score == best_score
                    && current.is_some_and(|c| c == pid)
                    && current.is_some_and(|c| c != best_pid)
            }
        };
        if better {
            best = Some((pid, score));
        }
    }
    best.map(|(pid, _)| pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sg_transport::quic::{GatewayQuic, client_tls, server_tls};
    use sg_tun::LoopbackTun;
    use sg_tun::TunConfig;
    use std::collections::HashSet;

    #[test]
    fn choose_path_ranks_healthiest_eligible() {
        let paths = [PathId::new(1), PathId::new(2), PathId::new(3)];
        let mut metrics = HashMap::new();

        // No metrics → all eligible-by-default, lowest id wins; ties keep
        // the current active path when one is given.
        assert_eq!(choose_path(&metrics, &paths, None), Some(PathId::new(1)));
        assert_eq!(
            choose_path(&metrics, &paths, Some(PathId::new(2))),
            Some(PathId::new(2)),
            "an idle tie never re-announces the active path"
        );

        // Unreachable path is never chosen even if it is first.
        metrics.insert(
            PathId::new(1),
            PathMetrics {
                reachable: false,
                ..Default::default()
            },
        );
        assert_eq!(choose_path(&metrics, &paths, None), Some(PathId::new(2)));

        // Healthy path 3 outranks the unreported path 2.
        metrics.insert(
            PathId::new(3),
            PathMetrics {
                reachable: true,
                srtt_ms: 20,
                loss: 0.01,
                available_kbps: 50_000,
                ..Default::default()
            },
        );
        assert_eq!(
            choose_path(&metrics, &paths, Some(PathId::new(3))),
            Some(PathId::new(3))
        );

        // A degraded (high-loss) healthy-looking path loses to a clean one.
        metrics.insert(
            PathId::new(2),
            PathMetrics {
                reachable: true,
                srtt_ms: 20,
                loss: 0.50,
                available_kbps: 50_000,
                ..Default::default()
            },
        );
        assert_eq!(
            choose_path(&metrics, &paths, Some(PathId::new(2))),
            Some(PathId::new(3))
        );
    }

    fn fake_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut v = vec![
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 0x40, 0x01, 0x00, 0x00, src[0], src[1],
            src[2], src[3], dst[0], dst[1], dst[2], dst[3],
        ];
        v.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00]);
        v
    }

    #[tokio::test]
    async fn client_engine_round_trip_single_path() {
        let (cert_der, key_der) = {
            let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (c.cert.der().to_vec(), c.key_pair.serialize_der())
        };
        let server_cfg = server_tls(&cert_der, &key_der).unwrap();
        let client_cfg = client_tls(&cert_der).unwrap();

        let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = gateway.local_addr().unwrap();

        // Naive echo gateway: answer the bootstrap Control/Init with an Ack,
        // and bounce every data envelope back to the client as Data.
        let server = gateway.clone();
        let echo_task = tokio::spawn(async move {
            let path = server.accept(PathId::new(1)).await.unwrap();
            loop {
                let e = match path.recv().await {
                    Ok(e) => e,
                    Err(_) => break,
                };
                let reply = match e.packet_type {
                    PacketType::Control => {
                        let b = e.session_id.as_guid().as_bytes();
                        let sid = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                        Envelope {
                            version: VERSION,
                            packet_type: PacketType::Control,
                            flags: 0,
                            path_id: e.path_id,
session_id: e.session_id,
                            sequence: e.sequence,
                            timestamp_ms: e.timestamp_ms,
                            payload: sg_protocol::control::ControlMsg::Ack { sid }
                                .encode()
                                .unwrap(),
                        }
                    }
                    _ => Envelope {
                        version: VERSION,
                        packet_type: PacketType::Data,
                        flags: 0,
                        path_id: e.path_id,
                        session_id: e.session_id,
                        sequence: e.sequence,
                        timestamp_ms: e.timestamp_ms,
                        payload: e.payload.clone(),
                    },
                };
                let _ = path.send(reply).await;
            }
        });

        let tun = LoopbackTun::with_config(TunConfig::default());
        let session_id = sg_session::session_id_from_wire(0x12345678);
        let mut handle = start(
            tun,
            ClientOptions {
                addr,
                server_name: "localhost".into(),
                client_config: client_cfg,
                keepalive_interval: Duration::from_secs(3600),
                probe_interval: Duration::from_secs(3600),
                probe_timeout: Duration::from_secs(3600),
                probe_failure_threshold: 2,
                redundancy_loss_threshold: 0.0,
            },
            session_id,
            &[PathId::new(1)],
            "unit-test-ticket",
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Uplink: inject a local packet; the engine should digits it out.
        let up = fake_packet([10, 0, 85, 2], [8, 8, 8, 8]);
        handle.tun.lock().await.enqueue(Bytes::from(up.clone()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(handle.counters().await.datagrams_to_gateway, 1);

        // Downlink: the echo gateway bounces the same bytes back; the
        // reader should place them back into the TUN.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let frames = handle.tun.lock().await.drain_outbound();
        assert!(
            frames.iter().any(|f| f.as_ref() == up.as_slice()),
            "echoed packet should return to the TUN"
        );
        assert_eq!(handle.counters().await.frames_to_host, 1);

        handle.stop().await;
        echo_task.abort();
    }

    /// Echo gateway for probe/health tests: answers the bootstrap Control/Init
    /// with an Ack, bounces Data back, and echoes Probe as a PathStatus. The
    /// `silent` set of path ids drops probe replies, simulating a link whose
    /// QUIC connection is alive but which no longer reaches the gateway.
    fn spawn_echo_gateway(
        server: GatewayQuic,
        paths: Vec<PathId>,
        silent: std::collections::HashSet<PathId>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut handles = Vec::new();
            for pid in paths {
                let s = server.clone();
                let silent = silent.clone();
                handles.push(tokio::spawn(async move {
                    let path = match s.accept(pid).await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    loop {
                        let e = match path.recv().await {
                            Ok(e) => e,
                            Err(_) => break,
                        };
                        let reply = match e.packet_type {
                            PacketType::Control => {
                                let b = e.session_id.as_guid().as_bytes();
                                let sid = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                                Envelope {
                                    version: VERSION,
                                    packet_type: PacketType::Control,
                                    flags: 0,
                                    path_id: e.path_id,
session_id: e.session_id,
                                    sequence: e.sequence,
                                    timestamp_ms: e.timestamp_ms,
                                    payload: sg_protocol::control::ControlMsg::Ack { sid }
                                        .encode()
                                        .unwrap(),
                                }
                            }
                            PacketType::Data => Envelope {
                                version: VERSION,
                                packet_type: PacketType::Data,
                                flags: 0,
                                path_id: e.path_id,
                                session_id: e.session_id,
                                sequence: e.sequence,
                                timestamp_ms: e.timestamp_ms,
                                payload: e.payload.clone(),
                            },
                            PacketType::Probe if silent.contains(&e.path_id) => continue,
                            PacketType::Probe => Envelope {
                                version: VERSION,
                                packet_type: PacketType::PathStatus,
                                flags: 0,
                                path_id: e.path_id,
                                session_id: e.session_id,
                                sequence: e.sequence,
                                timestamp_ms: e.timestamp_ms,
                                payload: e.payload.clone(),
                            },
                            _ => continue,
                        };
                        let _ = path.send(reply).await;
                    }
                }));
            }
            for h in handles {
                let _ = h.await;
            }
        })
    }

    #[tokio::test]
    async fn probes_meter_health_on_both_paths() {
        let (cert_der, key_der) = {
            let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (c.cert.der().to_vec(), c.key_pair.serialize_der())
        };
        let server_cfg = server_tls(&cert_der, &key_der).unwrap();
        let client_cfg = client_tls(&cert_der).unwrap();
        let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = gateway.local_addr().unwrap();
        let _echo = spawn_echo_gateway(gateway, vec![PathId::new(1), PathId::new(2)], HashSet::new());

        let tun = LoopbackTun::with_config(TunConfig::default());
        let session_id = sg_session::session_id_from_wire(0x42424242);
        let mut handle = start(
            tun,
            ClientOptions {
                addr,
                server_name: "localhost".into(),
                client_config: client_cfg,
                keepalive_interval: Duration::from_secs(3600),
                probe_interval: Duration::from_millis(25),
                probe_timeout: Duration::from_millis(50),
                probe_failure_threshold: 4,
                redundancy_loss_threshold: 0.0,
            },
            session_id,
            &[PathId::new(1), PathId::new(2)],
            "metering-test-ticket",
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(350)).await;

        let m1 = handle.path_metrics(PathId::new(1)).await;
        let m2 = handle.path_metrics(PathId::new(2)).await;
        assert!(m1.is_some(), "path 1 metered by its probe replies");
        assert!(m2.is_some(), "path 2 metered by its probe replies");
        for m in [&m1, &m2] {
            let m = m.as_ref().expect("path metered by its probe replies");
            assert!(m.reachable, "answering paths stay reachable");
            assert!(m.srtt_ms > 0, "RTT measured from probe replies");
            assert_eq!(m.loss, 0.0, "no lost probes on a healthy path");
        }
        let cc = handle.counters().await;
        assert!(cc.probes_sent >= 2, "both paths are being probed");
        assert_eq!(cc.soft_failures, 0, "no soft failure while probes answer");
        assert_eq!(cc.path_failures, 0, "no transport loss during metering");
        assert_eq!(
            handle.active_path().await,
            Some(PathId::new(1)),
            "initial active path is undisturbed while healthy"
        );

        handle.stop().await;
    }

#[tokio::test]
    async fn a_silent_path_fails_over_softly() {
        let (cert_der, key_der) = {
            let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (c.cert.der().to_vec(), c.key_pair.serialize_der())
        };
        let server_cfg = server_tls(&cert_der, &key_der).unwrap();
        let client_cfg = client_tls(&cert_der).unwrap();
        let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = gateway.local_addr().unwrap();

        // Path 1 never answers probes (its connection stays up), path 2 does.
        let silent = HashSet::from([PathId::new(1)]);
        let _echo =
            spawn_echo_gateway(gateway, vec![PathId::new(1), PathId::new(2)], silent);

        let tun = LoopbackTun::with_config(TunConfig::default());
        let session_id = sg_session::session_id_from_wire(0x51515151);
        let mut handle = start(
            tun,
            ClientOptions {
                addr,
                server_name: "localhost".into(),
                client_config: client_cfg,
                keepalive_interval: Duration::from_secs(3600),
                probe_interval: Duration::from_millis(30),
                probe_timeout: Duration::from_millis(50),
                probe_failure_threshold: 2,
                redundancy_loss_threshold: 0.0,
            },
            session_id,
            &[PathId::new(1), PathId::new(2)],
            "silent-path-test-ticket",
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;

        let cc = handle.counters().await;
        assert_eq!(cc.path_failures, 0, "the QUIC connection never died");
        assert!(
            cc.soft_failures >= 1,
            "silence past the probe threshold is a soft failure"
        );
        assert_eq!(
            handle.active_path().await,
            Some(PathId::new(2)),
            "the healthy standby takes over the downlink"
        );
let m1 = handle.path_metrics(PathId::new(1)).await;
        assert_eq!(
            m1.map(|m| m.reachable),
            Some(false),
            "the silent path is marked unreachable"
        );

        handle.stop().await;
    }

    #[tokio::test]
    async fn a_degraded_path_duplicates_to_the_healthy_standby() {
        let (cert_der, key_der) = {
            let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (c.cert.der().to_vec(), c.key_pair.serialize_der())
        };
        let server_cfg = server_tls(&cert_der, &key_der).unwrap();
        let client_cfg = client_tls(&cert_der).unwrap();
        let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = gateway.local_addr().unwrap();
        let _echo = spawn_echo_gateway(gateway, vec![PathId::new(1), PathId::new(2)], HashSet::new());

        // Phase 2 adaptive redundancy: the chosen active path is degraded (its loss
        // estimate crossed `redundancy_loss_threshold`) but still eligible, so
        // every packet is also sent as a `Duplicate` on the other eligible
        // path. Both links are degraded here so neither steals the downlink.
        let threshold = 0.10f32;
        let mut handle = start(
            LoopbackTun::with_config(TunConfig::default()),
            ClientOptions {
                addr,
                server_name: "localhost".into(),
                client_config: client_cfg,
                keepalive_interval: Duration::from_secs(3600),
                probe_interval: Duration::from_secs(3600),
                probe_timeout: Duration::from_secs(3600),
                probe_failure_threshold: 2,
                redundancy_loss_threshold: threshold,
            },
            sg_session::session_id_from_wire(0x61616161),
            &[PathId::new(1), PathId::new(2)],
            "duplication-test-ticket",
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Path 1 (active) is degraded the most; path 2 is eligible but also
        // degraded — the packet is still duplicated onto it as a safety net.
        handle
            .set_metrics(
                PathId::new(1),
                PathMetrics {
                    reachable: true,
                    srtt_ms: 20,
                    loss: 0.12,
                    available_kbps: 50_000,
                    ..Default::default()
                },
            )
            .await;
        handle
            .set_metrics(
                PathId::new(2),
                PathMetrics {
                    reachable: true,
                    srtt_ms: 15,
                    loss: 0.15,
                    available_kbps: 50_000,
                    ..Default::default()
                },
            )
            .await;

        let up = fake_packet([10, 0, 85, 2], [8, 8, 8, 8]);
        handle.tun.lock().await.enqueue(Bytes::from(up.clone()));
        tokio::time::sleep(Duration::from_millis(150)).await;

        let cc = handle.counters().await;
        assert_eq!(cc.datagrams_to_gateway, 2, "data + duplicate leave the client");
        assert_eq!(cc.duplicates_sent, 1, "one redundant copy for the degraded path");

        // The selected (least-degraded) path stays active: duplication is
        // reactive, not a re-rank.
        assert_eq!(
            handle.active_path().await,
            Some(PathId::new(1)),
            "the least-bad eligible path is chosen and stays active"
        );

        handle.stop().await;
    }
}
