//! Wordlyte-side status SDK integration tests (engineering step 16, spec
//! §21 / §22.5). They bring up the *real* authenticated status plane over
//! loopback TCP so the SDK is exercised against the same transport Wordlyte
//! Pro would consume.
//!
//! Provider plumbing: the engine's `StatusProvider` has a public test seam,
//! `StatusProvider::from_snapshot_fn`, so an external crate can hand
//! `spawn_status_server` a provider that answers a FIXED snapshot (injected
//! warnings, degraded mode) instead of live engine state. The seam test
//! below drives that path; the other two run the real engine + gateway
//! (`client::start(.., Some(endpoint))`), which constructs a live provider
//! internally — the engine's Bonding snapshot (2 bound paths) and the
//! wrong-token rejection both exercised end to end.
//!
//! All tests use loopback TCP on `127.0.0.1`, so they need no admin and run
//! on any host. The usual sleep cadence lets the engine's async reader loops
//! make progress (AGENTS.md Testing).

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use bytes::Bytes;
use serde::Deserialize;
use sg_core::PathId;
use sg_session::session_id_from_wire;
use sg_transport::quic::{GatewayQuic, client_tls, server_tls};
use sg_tun::{LoopbackTun, TunConfig};
use sg_wordlyte::{WordlyteClient, WordlyteStatus};
use streamguard_gateway::tunnel::{self, TunnelHandle};
use streamguard_service::client;
use streamguard_service::client::Counters;
use streamguard_service::ipc::{spawn_status_server, StatusEndpoint};
use streamguard_service::status::{
    Mode, PathStatus, StatusCounters, StatusProvider, StatusSnapshot,
};
use tokio::time::{Duration, sleep};

/// Reserves a concrete free loopback port by bind-and-release, so the
/// resolved `SocketAddr` is known to both the engine's status server (which
/// binds it) and the SDK client (which connects to it). Loopback TCP needs
/// no privileges.
fn loopback_tcp_endpoint() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// A running engine + gateway pair whose authenticated status server is
/// bound to the given loopback TCP endpoint, keyed by the session token.
struct Fixture {
    client: client::ClientHandle<LoopbackTun>,
    _gateway: TunnelHandle<LoopbackTun>,
    host: tokio::task::JoinHandle<()>,
    endpoint: SocketAddr,
    token: String,
}

impl Fixture {
    async fn spawn() -> Self {
        let (cert_der, key_der) = {
            let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (c.cert.der().to_vec(), c.key_pair.serialize_der())
        };
        let server_cfg = server_tls(&cert_der, &key_der).unwrap();
        let client_cfg = client_tls(&cert_der).unwrap();
        let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = gateway.local_addr().unwrap();

        let secret = b"sg-wordlyte-e2e-secret".to_vec();
        let host_tun = LoopbackTun::with_config(TunConfig {
            name: "sg-wan0".into(),
            address: "192.168.1.1".into(),
            prefix_len: 24,
            mtu: 1300,
        });
        let gw = tunnel::start(host_tun, gateway, secret.clone()).await;
        let host_task = tokio::spawn(host_echo(gw.tun.clone()));

        let client_tun = LoopbackTun::with_config(TunConfig {
            name: "sg-lan0".into(),
            address: "10.0.85.1".into(),
            prefix_len: 24,
            mtu: 1300,
        });
        let session = session_id_from_wire(0x0bad_c0de);
        let token = sg_auth::issue(&secret, session, 3600);
        let status_endpoint = loopback_tcp_endpoint();

        let client = client::start(
            client_tun,
            client::ClientOptions {
                addr,
                path_interfaces: Vec::new(),
                server_name: "localhost".into(),
                client_config: client_cfg,
                keepalive_interval: Duration::from_secs(3600),
                probe_interval: Duration::from_secs(3600),
                probe_timeout: Duration::from_secs(3600),
                probe_failure_threshold: 2,
                redundancy_loss_threshold: 0.0,
            },
            session,
            &[PathId::new(1), PathId::new(2)],
            &token,
            Some(streamguard_service::ipc::StatusEndpoint::Tcp(status_endpoint)),
        )
        .await
        .expect("engine starts with the status plane");

        sleep(Duration::from_millis(150)).await;

        Self {
            client,
            _gateway: gw,
            host: host_task,
            endpoint: status_endpoint,
            token,
        }
    }
}

/// Drains the host TUN's outbound traffic and echoes it back as an ICMP
/// reply, so the engine's downlink loop has real frames to move and the
/// status counters are live. Same shape as the engine's own e2e fixtures.
async fn host_echo(tun: Arc<tokio::sync::Mutex<LoopbackTun>>) {
    loop {
        for packet in tun.lock().await.drain_outbound() {
            if packet.len() >= 20 && (packet[0] >> 4) == 4 {
                let mut reply = packet.to_vec();
                reply.swap(12, 16);
                reply.swap(13, 17);
                reply.swap(14, 18);
                reply.swap(15, 19);
                // Turn the echoed ICMP request into a reply.
                if reply.len() >= 22 {
                    reply[20] = 0; // type: echo reply
                    reply[21] = 0; // code
                }
                tun.lock().await.enqueue(Bytes::from(reply));
            }
        }
        sleep(Duration::from_millis(2)).await;
    }
}

/// The SDK returns a `WordlyteStatus` that round-trips the live engine's
/// Bonding snapshot (2 bound paths) and serializes to the snake_case
/// contract (spec §21).
#[tokio::test]
async fn status_roundtrip_over_loopback_tcp() {
    let mut fx = Fixture::spawn().await;

    let mut client = WordlyteClient::with_tcp(fx.endpoint, &fx.token, 0x0bad_c0de).unwrap();
    let ws = client
        .status()
        .await
        .expect("correct token yields a WordlyteStatus");
    assert!(client.is_connected());

    // Bonding mode (both unmetered paths are eligible), two bound paths.
    assert!(ws.protection_enabled);
    assert_eq!(ws.mode, "bonding");
    assert_eq!(ws.path_quality.len(), 2, "both accredited paths are visible");
    assert!(ws.active_path.is_some(), "engine picked an active path");

    // The flat snake_case contract keys a marginal app relies on.
    let v: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&ws).unwrap()).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "protection_enabled",
        "mode",
        "active_path",
        "gateway_connected",
        "aggregate_available_kbps",
        "active_paths",
        "path_quality",
        "warnings",
    ] {
        assert!(obj.contains_key(key), "missing contract key {key:?}");
    }
    // And it deserializes back (a marginal app round-trips its blob).
    let back = WordlyteStatus::deserialize(&v).unwrap();
    assert_eq!(back, ws);

    fx.client.stop().await;
    fx.host.abort();
}

/// A client with the wrong token fails to authenticate (EOF on the first
/// snapshot read surfaces as an `Error::Auth`).
#[tokio::test]
async fn wrong_token_fails_with_auth_error() {
    let mut fx = Fixture::spawn().await;

    let mut rogue = WordlyteClient::with_tcp(fx.endpoint, "wrong-token", 0x0bad_c0de).unwrap();
    let err = rogue
        .status()
        .await
        .expect_err("the server rejects the bad MAC and closes");
    assert!(
        matches!(err, sg_core::error::Error::Auth(_)),
        "wrong token is an auth error, got: {err:?}"
    );
    assert!(!rogue.is_connected());

    // The legitimate client still works afterwards.
    let mut legit = WordlyteClient::with_tcp(fx.endpoint, &fx.token, 0x0bad_c0de).unwrap();
    let ws = legit.status().await.expect("legit client connects after rejection");
    assert_eq!(ws.mode, "bonding");

    fx.client.stop().await;
    fx.host.abort();
}

/// The `StatusProvider::from_snapshot_fn` seam lets an external harness
/// stand up `spawn_status_server` with a controlled snapshot — injected
/// warnings, degraded mode — and round-trips it through the real
/// authenticated loopback transport (spec §21).
#[tokio::test]
async fn controlled_snapshot_with_warnings_round_trips() {
    let endpoint = loopback_tcp_endpoint();
    let token = "wordlyte-seam-token";

    let provider = StatusProvider::from_snapshot_fn(|| StatusSnapshot {
        session_prefix: 0x0bad_c0de,
        protecting: true,
        mode: Mode::ActiveStandby,
        paths: vec![PathStatus {
            path_id: 1,
            reachable: true,
            rtt_ms: 18,
            srtt_ms: 17,
            jitter_ms: 3,
            loss: 0.05,
            available_kbps: 4200,
            stability_secs: 240,
        }],
        aggregate_kbps: 4200,
        active_path: Some(1),
        counters: StatusCounters::default(),
        warnings: vec!["cellular cap active".to_string()],
    });
    let server = spawn_status_server(
        StatusEndpoint::Tcp(endpoint),
        provider,
        token,
        Arc::new(tokio::sync::Mutex::new(Counters::default())),
    )
    .await
    .expect("status server with a fixed provider binds and serves");

    let addr = match server.endpoint() {
        StatusEndpoint::Tcp(addr) => *addr,
        #[cfg(windows)]
        StatusEndpoint::NamedPipe(_) => panic!("fixture uses loopback TCP"),
    };

    let mut client = WordlyteClient::with_tcp(addr, token, 0x0bad_c0de).unwrap();
    let ws = client
        .status()
        .await
        .expect("the seam snapshot is reachable through the SDK");
    assert!(ws.protection_enabled);
    assert_eq!(ws.mode, "active_standby", "mode maps to the stable string");
    assert!(ws.gateway_connected);
    assert_eq!(ws.aggregate_available_kbps, 4200);
    assert_eq!(ws.active_paths, vec![1]);
    assert_eq!(ws.warnings, vec!["cellular cap active".to_string()]);
    let pq = &ws.path_quality[0];
    assert_eq!(
        (pq.path_id, pq.rtt_ms, pq.loss_percent, pq.available_kbps),
        (1, 18, 5, 4200),
        "path quality sub-keys survive the real wire round-trip"
    );

    server.stop();
}
