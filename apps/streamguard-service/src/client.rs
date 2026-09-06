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
//!   `DefaultScorer`) and send it.
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
}

/// Aggregate counters exposed to tests after the engine runs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counters {
    pub paths: u64,
    /// IP packets written into the local TUN by downlink readers.
    pub frames_to_host: u64,
    /// Uplink envelopes sent to the gateway.
    pub datagrams_to_gateway: u64,
    /// Sequences rejected by the downlink reorder window.
    pub duplicates_dropped: u64,
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
}

/// Opens one QUIC path to the gateway per entry, authenticates each with the
/// v1 bootstrap handshake (`token` = gateway-signed session ticket), binds
/// the accredited paths to the session, then starts the uplink + downlink
/// loops.
pub async fn start<T: Tun + Send + 'static>(
    tun: T,
    addr: std::net::SocketAddr,
    server_name: &str,
    client_config: quinn::ClientConfig,
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
        let path = connect_path(addr, server_name, client_config.clone(), path_id).await?;
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

    let shared = Arc::new(Shared {
        session: Mutex::new(session),
        metrics: Mutex::new(HashMap::new()),
    });

    // Spawn one downlink reader per bound path.
    let mut reader_handles = Vec::new();
    for (path_id, transport) in transports {
        reader_handles.push(tokio::spawn(reader_loop(
            transport,
            path_id,
            tun.clone(),
            shared.clone(),
            counters.clone(),
        )));
    }

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let run = tokio::spawn(run_loop(
        tun.clone(),
        shared.clone(),
        counters.clone(),
        shutdown_rx,
        reader_handles,
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
) {
    let mut uplink_task = tokio::spawn(uplink_loop(tun, shared.clone(), counters));
    tokio::select! {
        _ = &mut shutdown => {}
        res = &mut uplink_task => { if let Err(e) = res { tracing::warn!(error = %e, "uplink loop exited"); } }
    }
    uplink_task.abort();
    for h in reader_handles {
        h.abort();
    }
}

// ---------------------------------------------------------------------------
// Downlink reader – one task per path
// ---------------------------------------------------------------------------

async fn reader_loop<T: Tun + Send + 'static>(
    transport: Arc<dyn PathTransport>,
    _path_id: PathId,
    tun: Arc<Mutex<T>>,
    shared: Arc<Shared>,
    counters: Arc<Mutex<Counters>>,
) {
    loop {
        let envelope = match transport.recv().await {
            Ok(e) => e,
            Err(_) => break, // connection closed
        };
        match envelope.packet_type {
            // Dedup against the shared per-session window, then inject.
            PacketType::Data | PacketType::Duplicate => {
                let is_new = {
                    let mut sess = shared.session.lock().await;
                    sess.accept_incoming(envelope.sequence)
                };
                if envelope.packet_type == PacketType::Duplicate || !is_new {
                    counters.lock().await.duplicates_dropped += 1;
                    continue;
                }
                counters.lock().await.frames_to_host += 1;
                let mut t = tun.lock().await;
                let _ = t.write(&envelope.payload);
            }
            // Control / Probe / Keepalive / PathStatus are handled by the
            // health/session logic in later milestones.
            _ => {}
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

        // Sequence + pick the healthiest eligible path, then send.
        let (seq, path_id, session_id) = {
            let mut sess = shared.session.lock().await;
            let seq = sess.next_sequence();
            let best = {
                let metrics = shared.metrics.lock().await;
                choose_path(&metrics, sess.path_ids().collect::<Vec<_>>().as_slice())
            };
            let best = match best {
                Some(p) => p,
                None => continue,
            };
            let _ = sess.set_active_path(best);
            (seq, best, sess.session_id())
        };

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
    }
}

/// Picks the eligible path with the highest score among `paths`; an
/// unmetered path is assumed eligible (initial active/standby phase).
/// Ineligible (e.g. unreachable) paths are never chosen.
fn choose_path(metrics: &HashMap<PathId, PathMetrics>, paths: &[PathId]) -> Option<PathId> {
    let scorer = DefaultScorer::default();
    let mut best: Option<(PathId, f32)> = None;
    for pid in paths {
        let score = match metrics.get(pid) {
            Some(m) if m.is_eligible() => scorer.score(m),
            Some(_) => -1.0, // metered but ineligible
            None => 0.0,     // no measurement yet → eligible-by-default
        };
        match best {
            None => best = Some((*pid, score)),
            Some((_, s)) if score > s => best = Some((*pid, score)),
            _ => {}
        }
    }
    best.map(|(pid, _)| pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sg_core::Sequence;
    use sg_transport::quic::{GatewayQuic, client_tls, server_tls};
    use sg_tun::LoopbackTun;
    use sg_tun::TunConfig;

    #[test]
    fn choose_path_ranks_healthiest_eligible() {
        let paths = [PathId::new(1), PathId::new(2), PathId::new(3)];
        let mut metrics = HashMap::new();

        // No metrics → all eligible-by-default, first one wins.
        assert_eq!(choose_path(&metrics, &paths), Some(PathId::new(1)));

        // Unreachable path is never chosen even if it is first.
        metrics.insert(
            PathId::new(1),
            PathMetrics {
                reachable: false,
                ..Default::default()
            },
        );
        assert_eq!(choose_path(&metrics, &paths), Some(PathId::new(2)));

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
        assert_eq!(choose_path(&metrics, &paths), Some(PathId::new(3)));

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
        assert_eq!(choose_path(&metrics, &paths), Some(PathId::new(3)));
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
                            sequence: Sequence::new(e.sequence.get().wrapping_add(1_000_000)),
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
                        sequence: Sequence::new(e.sequence.get().wrapping_add(1_000_000)),
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
            addr,
            "localhost",
            client_cfg,
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
}
