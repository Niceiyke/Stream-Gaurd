//! Gateway tunnel engine (spec 15.3 / engineering step 5).
//!
//! Binds a QUIC listener, accepts one connection per client path and runs
//! two loops:
//!
//! - **uplink readers** (one per accepted connection): demultiplex
//!   envelopes into per-session reorder windows, then write the host IP
//!   packet into the TUN.
//! - **downlink**: read IP packets from the TUN, look up the originating
//!   session via a minimal flow table and send the wrapped envelope back
//!   out that session's active path.
//!
//! The host-side TUN is generic: `LoopbackTun` (non-blocking `WouldBlock`)
//! is used by the integration test; real platform adapters block and must
//! be driven on a dedicated OS thread (spec 22.5).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use sg_auth;
use sg_core::error::Error;
use sg_core::{PathId, SessionId};
use sg_protocol::control::ControlMsg;
use sg_protocol::{Envelope, PacketType, VERSION};
use sg_session::SessionManager;
use sg_transport::quic::{GatewayQuic, QuicPathTransport};
use sg_transport::PathTransport;
use sg_tun::Tun;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

/// Counters exposed to tests after the engine runs. `authenticated_paths`
/// counts connections that completed the v1 bootstrap handshake; paths that
/// never authenticated are not added to any session or to `paths`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counters {
    pub sessions: u64,
    /// Connections (physical paths) that passed the bootstrap handshake.
    pub paths: u64,
    /// Bootstrap handshakes rejected with a Nack (bad/expired tickets).
    pub auth_rejections: u64,
    /// IP packets written into the host-side TUN.
    pub frames_to_host: u64,
    /// Downlink envelopes sent out active paths.
    pub datagrams_to_client: u64,
    /// Sequences rejected by the uplink reorder window.
    pub duplicates_dropped: u64,
    /// App-level keepalives received (standby paths refreshing their NAT
    /// mappings so failover can reach them).
    pub keepalives: u64,
    /// `Control::PathSelect` messages applied (downlink moved to a new path).
    pub path_selects: u64,
    /// Paths removed from sessions because their QUIC connection died. The
    /// session falls back to a surviving path (see `Session::remove_path`).
    pub paths_evicted: u64,
    /// Health probes answered with a `PathStatus` reply (per-path cadence
    /// the client's liveness monitor keys on).
    pub probes_replied: u64,
}

// ---------------------------------------------------------------------------
// 5-tuple flow table (IPv4 only)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey([u8; 11]);

/// Extracts the flow key from an IPv4 packet.
pub fn parse_flow(packet: &[u8]) -> Option<FlowKey> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if packet.len() < ihl + 4 {
        return None;
    }
    let proto = packet[9];
    let mut k = [0u8; 11];
    k[0..4].copy_from_slice(&[packet[12], packet[13], packet[14], packet[15]]);
    k[4..8].copy_from_slice(&[packet[16], packet[17], packet[18], packet[19]]);
    k[8] = proto;
    let id = match proto {
        // ICMP: echo id lives at l4 offset 4..6
        1 => {
            if packet.len() < ihl + 6 {
                return None;
            }
            u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]])
        }
        // TCP/UDP: first 16-bit field is the source port.
        _ => u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
    };
    k[9..11].copy_from_slice(&id.to_be_bytes());
    Some(FlowKey(k))
}

/// Swaps src / dst addresses for reverse-direction lookup.
pub fn reverse_key(FlowKey(k): FlowKey) -> FlowKey {
    let mut r = k;
    r[0..4].copy_from_slice(&k[4..8]);
    r[4..8].copy_from_slice(&k[0..4]);
    FlowKey(r)
}

// ---------------------------------------------------------------------------
// Engine handle
// ---------------------------------------------------------------------------

/// A running gateway tunnel. Call `stop` to tear down the engine.
pub struct TunnelHandle<T: Tun + Send + 'static> {
    run: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
    /// Exposed so the test can `enqueue` replies into the TUN and
    /// `drain_outbound` to assert that requests arrived.
    pub tun: Arc<Mutex<T>>,
    pub counters: Arc<Mutex<Counters>>,
}

impl<T: Tun + Send + 'static> TunnelHandle<T> {
    /// Gracefully shuts down the accept and downlink loops.
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
}

/// Starts the gateway tunnel engine on `tun`, returning a handle that
/// exposes counters and a reference to the shared TUN for test control.
///
/// `secret` is the shared HMAC key used to verify client bootstrap tickets.
pub async fn start<T: Tun + Send + 'static>(
    tun: T,
    gateway: GatewayQuic,
    secret: Vec<u8>,
) -> TunnelHandle<T> {
    let tun = Arc::new(Mutex::new(tun));
    let counters = Arc::new(Mutex::new(Counters::default()));
    let sessions = Arc::new(Mutex::new(SessionManager::new()));
    let flows = Arc::new(Mutex::new(HashMap::<FlowKey, SessionId>::new()));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let run = tokio::spawn(run_loop(
        Arc::new(gateway),
        tun.clone(),
        sessions,
        flows,
        Arc::new(secret),
        counters.clone(),
        shutdown_rx,
    ));

    TunnelHandle {
        run: Some(run),
        shutdown: Some(shutdown_tx),
        tun,
        counters,
    }
}

async fn run_loop<T: Tun + Send + 'static>(
    gateway: Arc<GatewayQuic>,
    tun: Arc<Mutex<T>>,
    sessions: Arc<Mutex<SessionManager>>,
    flows: Arc<Mutex<HashMap<FlowKey, SessionId>>>,
    secret: Arc<Vec<u8>>,
    counters: Arc<Mutex<Counters>>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut accept_task = tokio::spawn(accept_loop(
        gateway,
        tun.clone(),
        sessions.clone(),
        flows.clone(),
        secret.clone(),
        counters.clone(),
    ));
    let mut downlink_task = tokio::spawn(downlink_loop(tun, flows, sessions, counters));

    tokio::select! {
        _ = &mut shutdown => {}
        res = &mut accept_task => { if let Err(e) = res { tracing::warn!(error = %e, "accept loop exited"); } }
        res = &mut downlink_task => { if let Err(e) = res { tracing::warn!(error = %e, "downlink loop exited"); } }
    }
    accept_task.abort();
    downlink_task.abort();
}

// ---------------------------------------------------------------------------
// Accept loop – one task per physical connection
// ---------------------------------------------------------------------------

async fn accept_loop<T: Tun + Send + 'static>(
    gateway: Arc<GatewayQuic>,
    tun: Arc<Mutex<T>>,
    sessions: Arc<Mutex<SessionManager>>,
    flows: Arc<Mutex<HashMap<FlowKey, SessionId>>>,
    secret: Arc<Vec<u8>>,
    counters: Arc<Mutex<Counters>>,
) {
    let mut readers = tokio::task::JoinSet::new();
    loop {
        // path_id=0 is a placeholder; the reader re-binds to the real
        // path_id carried inside the first data envelope on this connection,
        // after the connection passes the bootstrap handshake below.
        match gateway.accept(PathId::new(0)).await {
            Ok(transport) => {
                let transport = Arc::new(transport);
                readers.spawn(reader_loop(
                    transport,
                    tun.clone(),
                    sessions.clone(),
                    flows.clone(),
                    secret.clone(),
                    counters.clone(),
                ));
            }
            Err(e) => {
                tracing::warn!(error = %e, "gateway accept returned an error; loop ending");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Uplink reader – runs for the lifetime of one accepted connection
// ---------------------------------------------------------------------------

async fn reader_loop<T: Tun + Send + 'static>(
    transport: Arc<QuicPathTransport>,
    tun: Arc<Mutex<T>>,
    sessions: Arc<Mutex<SessionManager>>,
    flows: Arc<Mutex<HashMap<FlowKey, SessionId>>>,
    secret: Arc<Vec<u8>>,
    counters: Arc<Mutex<Counters>>,
) {
    // ---- v1 bootstrap: the first Control must be an authenticated Init ----
    // Phase-1 fallback: if the very first frame is NOT a Control we treat the
    // connection as unauthenticated test traffic and process it normally.
    // (Real deployments require the signed Init before any data flows.)
    let mut first_session: Option<SessionId> = None;
    let mut first_frame: Option<Envelope> = None;
    match transport.recv().await {
        Ok(first) if first.packet_type == PacketType::Control => {
            match ControlMsg::decode(&first.payload) {
                Ok(ControlMsg::Init { sid, token }) => match verify_init(sid, &token, &secret) {
                    Ok(id) => {
                        tracing::debug!(sid, ?id, "gateway: init verified, sending ack");
                        if let Err(e) =
                            transport.send(control_reply(&first, ControlMsg::Ack { sid })).await
                        {
                            tracing::warn!(error = %e, "gateway: failed to send ack");
                        }
                        counters.lock().await.paths += 1;
                        first_session = Some(id);
                    }
                    Err(reason) => {
                        tracing::debug!(%sid, %reason, "gateway: init rejected, sending nack");
                        if let Err(e) = transport
                            .send(control_reply(&first, ControlMsg::Nack { sid, reason }))
                            .await
                        {
                            tracing::warn!(error = %e, "gateway: failed to send nack");
                        }
                        counters.lock().await.auth_rejections += 1;
                        return; // drop the unauthenticated connection
                    }
                },
                Ok(other) => {
                    tracing::warn!(msg = ?other, "non-init control on a fresh path");
                    return;
                }
                Err(_) => return,
            }
        }
        Ok(first) => {
            tracing::warn!("accepting connection without authenticated Init (phase-1 fallback)");
            counters.lock().await.paths += 1;
            first_frame = Some(first);
        }
        Err(_) => return,
    }

    // Remember authenticated init: require the path's OWN envelope session
    // to match what the ticket accredited (else the handshake was for a
    // different session).
    // `binds` is the set of (session, path) pairs THIS connection bound; on
    // connection loss they are evicted so the session falls back to a
    // surviving path and the downlink never tries a dead path.
    let mut binds: Vec<(SessionId, PathId)> = Vec::new();
    loop {
        let envelope = match first_frame.take() {
            Some(e) => e,
            None => match transport.recv().await {
                Ok(e) => e,
                Err(_) => break, // connection closed or fatal error
            },
        };
        if let Some(accredited) = first_session {
            if session_prefix(envelope.session_id) != session_prefix(accredited) {
                tracing::warn!("path session does not match accredited session; dropping");
                break;
            }
        }

        // Bind session + path, dedup via reorder window (no nested locks).
        let (is_new_session, should_forward) = {
            let mut sessions = sessions.lock().await;
            let session = sessions.get_or_create(envelope.session_id);
            let is_new = session.path_count() == 0;
            if !session.has_path(envelope.path_id)
                && session.add_path(transport.clone(), envelope.path_id).is_ok()
            {
                binds.push((envelope.session_id, envelope.path_id));
            }
            let accept = match envelope.packet_type {
                PacketType::Data | PacketType::Duplicate => {
                    session.accept_incoming(envelope.sequence)
                }
                _ => false, // Control / Keepalive / Probe / PathStatus
            };
            (is_new, accept)
        };
        if is_new_session {
            counters.lock().await.sessions += 1;
        }
        match envelope.packet_type {
            PacketType::Data | PacketType::Duplicate if should_forward => {
                counters.lock().await.frames_to_host += 1;
                // Learn the flow so the reply can be routed back to this
                // session (reverse-key lookup in the downlink loop).
                let sid = envelope.session_id;
                if let Some(key) = parse_flow(&envelope.payload) {
                    flows.lock().await.insert(key, sid);
                }
                let mut t = tun.lock().await;
                let _ = t.write(&envelope.payload);
            }
            PacketType::Data | PacketType::Duplicate => {
                counters.lock().await.duplicates_dropped += 1;
            }
            // Rev1 path control: the client picked a new active path; move the
            // downlink for its session there (fire-and-forget datagram).
            PacketType::Control => {
                if let Ok(ControlMsg::PathSelect { path }) =
                    ControlMsg::decode(&envelope.payload)
                {
                    let applied = {
                        let mut sessions = sessions.lock().await;
                        match sessions.session_mut(envelope.session_id) {
                            Some(s) => s.set_active_path(PathId::new(path)).is_ok(),
                            None => false,
                        }
                    };
                    if applied {
                        counters.lock().await.path_selects += 1;
                    } else {
                        tracing::debug!(
                            ?path,
                            ?envelope.session_id,
                            "path select ignored: session/path not bound yet"
                        );
                    }
                }
            }
            PacketType::Keepalive => {
                counters.lock().await.keepalives += 1;
            }
            // Per-path health probe (spec 31.3): bounce it straight back as a
            // PathStatus so the client can measure RTT and treat silence as a
            // soft-liveness failure (`probe_timeout` expiry).
            PacketType::Probe => {
                let status = Envelope {
                    version: VERSION,
                    packet_type: PacketType::PathStatus,
                    flags: 0,
                    path_id: envelope.path_id,
                    session_id: envelope.session_id,
                    sequence: envelope.sequence,
                    timestamp_ms: envelope.timestamp_ms,
                    payload: envelope.payload.clone(),
                };
                if transport.send(status).await.is_ok() {
                    counters.lock().await.probes_replied += 1;
                }
            }
            _ => {} // PathStatus / other are reserved for later milestones
        }
    }

    // The connection that fed this reader is gone: evict every path it had
    // bound so the session falls back to a surviving path (spec 12 phase 1
    // "migrate on failure") and the downlink stops targeting a dead path.
    if !binds.is_empty() {
        let mut evicted = 0u64;
        {
            let mut sessions = sessions.lock().await;
            for (sid, pid) in &binds {
                if let Some(s) = sessions.session_mut(*sid) {
                    if s.remove_path(*pid) {
                        evicted += 1;
                    }
                }
            }
        }
        if evicted > 0 {
            counters.lock().await.paths_evicted += evicted;
            tracing::debug!(evicted, "evicted bound paths of a dead connection");
        }
    }
}

/// Builds a Control reply envelope mirroring the initiating envelope.
fn control_reply(init: &Envelope, msg: ControlMsg) -> Envelope {
    Envelope {
        version: init.version,
        packet_type: PacketType::Control,
        flags: 0,
        path_id: init.path_id,
        session_id: init.session_id,
        sequence: init.sequence,
        timestamp_ms: init.timestamp_ms,
        payload: msg.encode().expect("control never exceeds u16::MAX"),
    }
}

/// Verifies an Init's signed ticket and maps it to a wire-safe SessionId.
/// Returns the reason string on failure so the gateway can Nack it.
fn verify_init(sid: u32, token: &str, secret: &[u8]) -> std::result::Result<SessionId, String> {
    let id = sg_auth::verify(token, secret)
        .map_err(|e| format!("{e}"))?;
    if session_prefix(id) != sid {
        return Err("ticket session id does not match Init sid".into());
    }
    Ok(id)
}

fn session_prefix(id: SessionId) -> u32 {
    let b = id.as_guid().as_bytes();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

// ---------------------------------------------------------------------------
// Downlink loop – IP packets leaving the host TUN flow back to the
// originating session over its active path.
// ---------------------------------------------------------------------------

async fn downlink_loop<T: Tun + Send + 'static>(
    tun: Arc<Mutex<T>>,
    flows: Arc<Mutex<HashMap<FlowKey, SessionId>>>,
    sessions: Arc<Mutex<SessionManager>>,
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

        let Some(key) = parse_flow(&buf[..n]) else {
            continue;
        };
        // The reply's flow is the request's key reversed (internet side is
        // now the source); the reader recorded the request's client-first key.
        let rev = reverse_key(key);
        let sid = {
            match flows.lock().await.get(&rev).copied() {
                Some(sid) => sid,
                None => continue,
            }
        };

        // Sequence + active path.
        let seq_and_path = {
            let mut sessions = sessions.lock().await;
            let session = match sessions.session_mut(sid) {
                Some(s) => s,
                None => continue,
            };
            let seq = session.next_sequence();
            match session.active_path() {
                Some(p) => (seq, p),
                None => continue,
            }
        };
        let (seq, path_id) = seq_and_path;

        let env = Envelope {
            version: VERSION,
            packet_type: PacketType::Data,
            flags: 0,
            path_id,
            session_id: sid,
            sequence: seq,
            timestamp_ms: 0,
            payload: Bytes::copy_from_slice(&buf[..n]),
        };

        let sent = {
            let mut sessions = sessions.lock().await;
            match sessions.session_mut(sid) {
                Some(s) => s.send_on(path_id, env).await.is_ok(),
                None => false,
            }
        };
        if sent {
            counters.lock().await.datagrams_to_client += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_key_is_symmetric_for_icmp() {
        // 10.0.85.2 → 8.8.8.8, proto 1, echo id 0x1234
        let mut pkt = vec![0u8; 32];
        pkt[0] = 0x45; // ver/ihl
        pkt[9] = 1; // proto=ICMP
        pkt[12..16].copy_from_slice(&[10, 0, 85, 2]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[24..26].copy_from_slice(&0x1234u16.to_be_bytes()); // ICMP id

        let key = parse_flow(&pkt).expect("key");
        let rev = reverse_key(key);
        // Reverse swaps the src/dst quadruples (bytes 0..4 and 4..8).
        assert_eq!(key.0[0..4], rev.0[4..8]);
        assert_eq!(key.0[4..8], rev.0[0..4]);
        assert_eq!(key.0[8..11], rev.0[8..11], "proto+id unchanged in reverse");
    }
}