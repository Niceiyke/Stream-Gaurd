//! Authenticated status-plane integration test (engineering step 12, Phase
//! T1): the client engine (`client::start` with `Some(StatusEndpoint)`)
//! exposes the live status plane, and `StatusClient` pulls `StatusSnapshot`s
//! over the same transport the desktop UI will talk to.
//!
//! Proves the composition end to end over real QUIC:
//! - the engine spawns the IPC server bound to the *same* session token it
//!   used for the QUIC bootstrap;
//! - the snapshot projects real engine state (both accredited paths,
//!   Bonding mode, live counters);
//! - an unknown token is rejected once, counted, and the engine keeps
//!   serving legitimate clients.

use std::sync::Arc;

use bytes::Bytes;
use sg_core::PathId;
use sg_session::session_id_from_wire;
use sg_transport::quic::{GatewayQuic, client_tls, server_tls};
use sg_tun::{LoopbackTun, TunConfig};
use streamguard_gateway::tunnel::{self, TunnelHandle};
use streamguard_service::client;
use streamguard_service::ipc::{StatusClient, StatusEndpoint};
use streamguard_service::status::Mode;
use tokio::time::{Duration, sleep};

/// The status plane rides the platform-native loopback transport: the named
/// pipe on Windows (where the privileged service runs), TCP on other hosts.
fn status_endpoint(tag: &str) -> StatusEndpoint {
    #[cfg(windows)]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        StatusEndpoint::NamedPipe(format!(
            r"\\.\pipe\streamguard-status-{tag}-{}-{nanos}",
            std::process::id()
        ))
    }
    #[cfg(not(windows))]
    {
        StatusEndpoint::Tcp("127.0.0.1:0".parse().unwrap())
    }
}

fn icmp_request(src: [u8; 4], dst: [u8; 4], echo_id: u16) -> Vec<u8> {
    let mut v = vec![
        0x45, 0x00, 0x00, 0x1c, //
        0x00, 0x00, 0x00, 0x00, //
        0x40, 0x01, 0x00, 0x00, //
        src[0], src[1], src[2], src[3],
        dst[0], dst[1], dst[2], dst[3],
    ];
    let mut icmp = vec![0x08, 0x00, 0x00, 0x00];
    icmp.extend_from_slice(&echo_id.to_be_bytes());
    icmp.extend_from_slice(&[0x00, 0x01]);
    v.extend_from_slice(&icmp);
    v
}

/// Stand-in internet host: echoes frames the gateway forwards. Same shape as
/// the `e2e` fixture so round-trip counters are comparable.
async fn host_echo(tun: Arc<tokio::sync::Mutex<LoopbackTun>>) {
    loop {
        let forwarded = tun.lock().await.drain_outbound();
        for packet in forwarded {
            if packet[0] >> 4 != 4 || packet.len() < 28 {
                continue;
            }
            let src = [packet[12], packet[13], packet[14], packet[15]];
            let dst = [packet[16], packet[17], packet[18], packet[19]];
            let echo_id = u16::from_be_bytes([packet[24], packet[25]]);
            tun.lock()
                .await
                .enqueue(Bytes::from(icmp_reply(src, dst, echo_id)));
        }
        sleep(Duration::from_millis(2)).await;
    }
}

fn icmp_reply(dst: [u8; 4], src: [u8; 4], echo_id: u16) -> Vec<u8> {
    let mut v = vec![
        0x45, 0x00, 0x00, 0x1c, //
        0x00, 0x00, 0x00, 0x00, //
        0x40, 0x01, 0x00, 0x00, //
        src[0], src[1], src[2], src[3],
        dst[0], dst[1], dst[2], dst[3],
    ];
    let mut icmp = vec![0x00, 0x00, 0x00, 0x00];
    icmp.extend_from_slice(&echo_id.to_be_bytes());
    icmp.extend_from_slice(&[0x00, 0x01]);
    v.extend_from_slice(&icmp);
    v
}

/// One running engine + gateway pair, with the status server bound to
/// `endpoint` and the wire session id used by every component.
struct Fixture {
    client: client::ClientHandle<LoopbackTun>,
    _gateway: TunnelHandle<LoopbackTun>,
    host: tokio::task::JoinHandle<()>,
    endpoint: StatusEndpoint,
    session: sg_core::SessionId,
    token: String,
}

impl Fixture {
    async fn spawn(endpoint: StatusEndpoint) -> Self {
        let (cert_der, key_der) = {
            let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (c.cert.der().to_vec(), c.key_pair.serialize_der())
        };
        let server_cfg = server_tls(&cert_der, &key_der).unwrap();
        let client_cfg = client_tls(&cert_der).unwrap();
        let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = gateway.local_addr().unwrap();

        let secret = b"status-ipc-e2e-secret".to_vec();
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
        let client = client::start(
            client_tun,
            client::ClientOptions {
                addr,
                path_interfaces: Vec::new(),
                server_name: "localhost".into(),
                client_config: client_cfg,
                // Keepalives/probes parked: deterministic counters.
                keepalive_interval: Duration::from_secs(3600),
                probe_interval: Duration::from_secs(3600),
                probe_timeout: Duration::from_secs(3600),
                probe_failure_threshold: 2,
                redundancy_loss_threshold: 0.0,
            },
            session,
            &[PathId::new(1), PathId::new(2)],
            &token,
            Some(endpoint.clone()),
        )
        .await
        .expect("engine starts with the status plane");

        // Prove the plumbing is live before returning: one snapshot over the
        // real endpoint, projected from the running engine.
        sleep(Duration::from_millis(150)).await;
        let mut probe = StatusClient::for_session(endpoint.clone(), &token, session)
            .connect()
            .await
            .expect("status plane accepts the engine session token");
        let snap = probe
            .snapshot()
            .await
            .expect("status plane serves a snapshot");
        assert_eq!(snap.session_prefix, 0x0bad_c0de);
        assert_eq!(snap.paths.len(), 2, "both accredited paths are visible");
        drop(probe);

        Self {
            client,
            _gateway: gw,
            host: host_task,
            endpoint,
            session,
            token,
        }
    }
}

/// The engine publishes a live, accurate snapshot: Bonding mode, both paths,
/// and counters that move with real traffic.
#[tokio::test]
async fn status_plane_reports_live_engine_snapshot() {
    let mut fx = Fixture::spawn(status_endpoint("live")).await;

    let mut session = StatusClient::for_session(fx.endpoint.clone(), &fx.token, fx.session)
        .connect()
        .await
        .expect("legitimate client connects");
    let snap = session.snapshot().await.unwrap();
    assert_eq!(snap.mode, Mode::Bonding, "both paths unmetered = eligible");
    assert!(snap.protecting, "bonding protects the session");
    assert_eq!(snap.paths.len(), 2);
    assert!(snap.active_path.is_some(), "the engine picked an active path");
    assert_eq!(snap.counters.status_auth_failures, 0);

    // A round trip moves the counters; the snapshot must reflect it.
    fx.client
        .tun
        .lock()
        .await
        .enqueue(Bytes::from(icmp_request([10, 0, 85, 2], [8, 8, 8, 8], 0x2222)));
    sleep(Duration::from_millis(150)).await;

    let snap = session.snapshot().await.unwrap();
    assert!(
        snap.counters.frames_to_host >= 1,
        "the echo request reached the host TUN: {:?}",
        snap.counters
    );
    assert_eq!(
        snap.counters.frames_to_host,
        fx.client.counters().await.frames_to_host,
        "the snapshot projects the live counters"
    );

    session.close().await;
    fx.client.stop().await;
    fx.host.abort();
}

/// An unknown token is rejected exactly once — surfaced as an EOF on the
/// first snapshot, counted in the engine, and harmless to subsequent
/// legitimate clients.
#[tokio::test]
async fn status_plane_rejects_unknown_token() {
    let mut fx = Fixture::spawn(status_endpoint("reject")).await;

    let mut rogue = StatusClient::for_session(fx.endpoint.clone(), "unknown-token", fx.session)
        .connect()
        .await
        .expect("the rogue connect is indistinguishable from a legit one");
    assert!(
        rogue.snapshot().await.is_err(),
        "the server rejects the bad MAC and closes"
    );

    let mut counted = false;
    for _ in 0..50 {
        if fx.client.counters().await.status_auth_failures >= 1 {
            counted = true;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(counted, "the rejection is counted once");
    assert_eq!(fx.client.counters().await.status_auth_failures, 1);

    // The legitimate client still works afterwards.
    let mut legit = StatusClient::for_session(fx.endpoint.clone(), &fx.token, fx.session)
        .connect()
        .await
        .expect("legitimate client connects after the rejection");
    let snap = legit.snapshot().await.unwrap();
    assert_eq!(snap.session_prefix, 0x0bad_c0de);
    legit.close().await;

    fx.client.stop().await;
    fx.host.abort();
}