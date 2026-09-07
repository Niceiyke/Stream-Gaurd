//! End-to-end tunnel test (engineering step 7): the client service engine
//! (apps/streamguard-service) talks to the gateway tunnel engine
//! (apps/streamguard-gateway) over real QUIC, sharing one host-side TUN.
//!
//! Proves the composition the user asked for:
//! - one logical session, two physical QUIC paths, opened by
//!   `client::start` and demultiplexed by the gateway engine;
//! - an ICMP echo round-trip: local TUN → client uplink → gateway TUN →
//!   host reply → flow-routed back into the client TUN;
//! - a health-driven active-path switch (`set_metrics`) mid-session with
//!   sequence continuity (no duplicates, both replies delivered in order).

use bytes::Bytes;
use sg_core::PathId;
use sg_health::PathMetrics;
use sg_session::session_id_from_wire;
use sg_transport::quic::{GatewayQuic, client_tls, server_tls};
use sg_tun::{LoopbackTun, TunConfig};
use streamguard_gateway::tunnel;
use streamguard_service::client;
use tokio::time::{Duration, sleep};

fn icmp_request(src: [u8; 4], dst: [u8; 4], echo_id: u16) -> Vec<u8> {
    let mut v = vec![
        0x45, 0x00, 0x00, 0x1c, // IP version/length
        0x00, 0x00, 0x00, 0x00, // id/flags/frag
        0x40, 0x01, 0x00, 0x00, // ttl/proto=ICMP/checksum
        src[0], src[1], src[2], src[3],
        dst[0], dst[1], dst[2], dst[3],
    ];
    let mut icmp = vec![0x08, 0x00, 0x00, 0x00];
    icmp.extend_from_slice(&echo_id.to_be_bytes());
    icmp.extend_from_slice(&[0x00, 0x01]); // seq
    v.extend_from_slice(&icmp);
    v
}

fn icmp_reply(dst: [u8; 4], src: [u8; 4], echo_id: u16) -> Vec<u8> {
    let mut v = vec![
        0x45, 0x00, 0x00, 0x1c, //
        0x00, 0x00, 0x00, 0x00, //
        0x40, 0x01, 0x00, 0x00, //
        src[0], src[1], src[2], src[3], // internet side is source
        dst[0], dst[1], dst[2], dst[3],
    ];
    let mut icmp = vec![0x00, 0x00, 0x00, 0x00];
    icmp.extend_from_slice(&echo_id.to_be_bytes());
    icmp.extend_from_slice(&[0x00, 0x01]);
    v.extend_from_slice(&icmp);
    v
}

/// A stand-in "internet host": pulls the packets the gateway forwards out
/// of its host TUN (the engine `write`s them) and enqueues an ICMP echo
/// reply back into it (the downlink loop `read`s those). Swaps src/dst so
/// the gateway's reverse-flow lookup routes the reply to the session.
async fn host_echo(tun: std::sync::Arc<tokio::sync::Mutex<LoopbackTun>>) {
    loop {
        let forwarded = tun.lock().await.drain_outbound();
        for packet in forwarded {
            if packet[0] >> 4 != 4 || packet.len() < 28 {
                continue;
            }
            let src = [packet[12], packet[13], packet[14], packet[15]];
            let dst = [packet[16], packet[17], packet[18], packet[19]];
            // ICMP echo id at ihl(5*4=20) + 4 .. 6.
            let echo_id = u16::from_be_bytes([packet[24], packet[25]]);
            // icmp_reply(dst_param, src_param, ...): the *src_param* lands in
            // the IP source field, so the internet side (request dst) must be
            // passed as src_param. This makes reverse-flow lookup match.
            tun.lock().await.enqueue(Bytes::from(icmp_reply(src, dst, echo_id)));
        }
        sleep(Duration::from_millis(2)).await;
    }
}

#[tokio::test]
async fn client_and_gateway_engines_talk_over_two_paths() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    // Gateway engine on the host side.
    let secret = b"e2e-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut gw = tunnel::start(host_tun, gateway, secret.clone()).await;
    let host_task = tokio::spawn(host_echo(gw.tun.clone()));

    // Client engine on the device side: one session, two paths.
    let client_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-lan0".into(),
        address: "10.0.85.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let session = session_id_from_wire(0xfeedbeef);
    let token = sg_auth::issue(&secret, session, 3600);
    let mut client = client::start(
        client_tun,
client::ClientOptions {
            addr,
            path_interfaces: Vec::new(),
            server_name: "localhost".into(),
            client_config: client_cfg,
            // Keepalives are covered by `keepalives_refresh_all_paths`; keep
            // this test's counters deterministic by parking the cadence.
            keepalive_interval: Duration::from_secs(3600),
            probe_interval: Duration::from_secs(3600),
            probe_timeout: Duration::from_secs(3600),
            probe_failure_threshold: 2,
            redundancy_loss_threshold: 0.0,
        },
        session,
        &[PathId::new(1), PathId::new(2)],
        &token,
        None,
    )
    .await
    .unwrap();
    sleep(Duration::from_millis(150)).await;

    // Both physical paths registered after successful bootstrap handshakes.
    assert_eq!(
        gw.counters().await.paths,
        2,
        "both QUIC connections accredited"
    );
    assert_eq!(gw.counters().await.auth_rejections, 0);

    // ---- round-trip 1 on the initial active path (path 1, unmetered) ----
    let req1 = icmp_request([10, 0, 85, 2], [8, 8, 8, 8], 0x1111);
    client
        .tun
        .lock()
        .await
        .enqueue(Bytes::from(req1.clone()));
    sleep(Duration::from_millis(150)).await;

    let cc = client.counters().await;
    assert_eq!(cc.datagrams_to_gateway, 1, "request 1 leaves the client");
    assert_eq!(cc.duplicates_dropped, 0);
    assert_eq!(
        gw.counters().await.sessions,
        1,
        "single device session learned from the wire id"
    );
    assert_eq!(gw.counters().await.frames_to_host, 1, "request 1 reaches host TUN");
    assert_eq!(
        gw.counters().await.path_selects,
        0,
        "the initial active path is not re-announced"
    );

    sleep(Duration::from_millis(250)).await;
    assert_eq!(
        gw.counters().await.datagrams_to_client,
        1,
        "gateway routed the reply"
    );
    let cc = client.counters().await;
    assert_eq!(cc.frames_to_host, 1, "reply 1 is delivered to the local TUN");
    let frames = client.tun.lock().await.drain_outbound();
    assert!(
        frames.contains(&Bytes::from(icmp_reply([10, 0, 85, 2], [8, 8, 8, 8], 0x1111))),
        "reply 1 (source 8.8.8.8) appears in the client TUN"
    );

    // ---- health-driven switch: path 2 now scores higher than path 1 ----
    client
        .set_metrics(
            PathId::new(1),
            PathMetrics {
                reachable: true,
                srtt_ms: 90,
                loss: 0.10,
                available_kbps: 2_000,
                ..Default::default()
            },
        )
        .await;
    client
        .set_metrics(
            PathId::new(2),
            PathMetrics {
                reachable: true,
                srtt_ms: 10,
                loss: 0.01,
                available_kbps: 50_000,
                ..Default::default()
            },
        )
        .await;

    let req2 = icmp_request([10, 0, 85, 2], [1, 1, 1, 1], 0x2222);
    client
        .tun
        .lock()
        .await
        .enqueue(Bytes::from(req2.clone()));
    sleep(Duration::from_millis(150)).await;

    assert_eq!(
        client.active_path().await,
        Some(PathId::new(2)),
        "uplink switched to the healthier path"
    );
    assert_eq!(client.counters().await.datagrams_to_gateway, 2);
    assert_eq!(gw.counters().await.frames_to_host, 2, "request 2 reaches host TUN");
    assert_eq!(
        gw.counters().await.path_selects,
        1,
        "the client steered the gateway's downlink to path 2"
    );

    // ---- replies 1 and 2 both return, in order, no duplicates ----
    sleep(Duration::from_millis(150)).await;
    let cc = client.counters().await;
    assert_eq!(cc.frames_to_host, 2, "both replies delivered across the switch");
    assert_eq!(cc.duplicates_dropped, 0);

    let frames = client.tun.lock().await.drain_outbound();
    assert!(
        frames.contains(&Bytes::from(icmp_reply(
            [10, 0, 85, 2],
            [1, 1, 1, 1],
            0x2222
        ))),
        "reply 2 (source 1.1.1.1) appears in the client TUN; reply 1 was drained earlier"
    );

    client.stop().await;
    gw.stop().await;
    host_task.abort();
}

#[tokio::test]
async fn keepalives_refresh_all_paths() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    let secret = b"keepalive-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut gw = tunnel::start(host_tun, gateway, secret.clone()).await;

    let client_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-lan0".into(),
        address: "10.0.85.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let session = session_id_from_wire(0xf00df00d);
    let token = sg_auth::issue(&secret, session, 3600);
    let mut client = client::start(
        client_tun,
client::ClientOptions {
            addr,
            path_interfaces: Vec::new(),
            server_name: "localhost".into(),
            client_config: client_cfg,
            keepalive_interval: Duration::from_millis(30),
            probe_interval: Duration::from_secs(3600),
            probe_timeout: Duration::from_secs(3600),
            probe_failure_threshold: 2,
            redundancy_loss_threshold: 0.0,
        },
        session,
        &[PathId::new(1), PathId::new(2)],
        &token,
        None,
    )
    .await
    .unwrap();

    // No data flows here: every packet on the wire is a keepalive, so the
    // client must emit on BOTH paths (the standby too) to keep NAT mappings
    // fresh for failover (spec 17 stable egress).
    sleep(Duration::from_millis(300)).await;
    assert!(
        client.counters().await.keepalives >= 4,
        "the client emits keepalives repeatedly on every bound path"
    );
    assert!(
        gw.counters().await.keepalives >= 4,
        "the gateway observes keepalives on both connections"
    );
    assert_eq!(gw.counters().await.paths, 2, "both paths accredited");
    assert_eq!(gw.counters().await.auth_rejections, 0);

    client.stop().await;
    gw.stop().await;
}

#[tokio::test]
async fn client_fails_over_when_the_active_path_dies() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    let secret = b"failover-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut gw = tunnel::start(host_tun, gateway, secret.clone()).await;
    let host_task = tokio::spawn(host_echo(gw.tun.clone()));

    let client_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-lan0".into(),
        address: "10.0.85.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let session = session_id_from_wire(0xcafebabe);
    let token = sg_auth::issue(&secret, session, 3600);
    let mut client = client::start(
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
        None,
    )
    .await
    .unwrap();
    sleep(Duration::from_millis(150)).await;
    assert_eq!(gw.counters().await.paths, 2, "both paths accredited");

    // ---- round trip on the initial active path (1) ----
    let req = icmp_request([10, 0, 85, 2], [8, 8, 8, 8], 0x1111);
    client
        .tun
        .lock()
        .await
        .enqueue(Bytes::from(req.clone()));
    sleep(Duration::from_millis(150)).await;
    assert_eq!(client.counters().await.datagrams_to_gateway, 1);
    sleep(Duration::from_millis(250)).await;
    assert_eq!(client.counters().await.frames_to_host, 1, "reply 1 delivered");

    // ---- sever the active path's QUIC connection (simulated link down) ----
    assert!(client.sever_path(PathId::new(1)).await, "path 1 was bound");

    // The client must detect the loss, mark the path unreachable, promote
// path 2 AND steer the gateway; the gateway must evict the dead path so
    // its downlink falls back to path 2 instead of a dead connection.
    let mut converged = false;
    for _ in 0..50 {
        if client.counters().await.path_failures >= 1
            && client.active_path().await == Some(PathId::new(2))
            && gw.counters().await.paths_evicted >= 1
        {
            converged = true;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(
        converged,
        "client detected the loss (path_failures), promoted the standby (active=2), \
         and the gateway evicted the dead path (paths_evicted); \
         snapshot: client pf={} active={:?} gw evicted={} gw selects={}",
        client.counters().await.path_failures,
        client.active_path().await,
        gw.counters().await.paths_evicted,
        gw.counters().await.path_selects,
    );
    assert!(
        client.counters().await.path_selects >= 1,
        "the client steered the gateway's downlink to path 2"
    );

    // ---- traffic keeps flowing over path 2 after the failover ----
    let req2 = icmp_request([10, 0, 85, 2], [1, 1, 1, 1], 0x2222);
    client
        .tun
        .lock()
        .await
        .enqueue(Bytes::from(req2.clone()));
    sleep(Duration::from_millis(150)).await;
    assert_eq!(
        client.counters().await.datagrams_to_gateway, 2,
"request 2 leaves the client after failover"
    );

    let mut replied = false;
    for _ in 0..50 {
        if client.counters().await.frames_to_host == 2 {
            replied = true;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(replied, "reply 2 arrives over the promoted path");
    let frames = client.tun.lock().await.drain_outbound();
    assert!(
        frames.contains(&Bytes::from(icmp_reply([10, 0, 85, 2], [1, 1, 1, 1], 0x2222))),
        "reply 2 goes to the client TUN"
    );

    client.stop().await;
    gw.stop().await;
    host_task.abort();
}

#[tokio::test]
async fn client_bonds_two_healthy_paths_by_weight() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    let secret = b"bonding-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut gw = tunnel::start(host_tun, gateway, secret.clone()).await;
    let host_task = tokio::spawn(host_echo(gw.tun.clone()));

    let client_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-lan0".into(),
        address: "10.0.85.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let session = session_id_from_wire(0xb0b0b0b0);
    let token = sg_auth::issue(&secret, session, 3600);
    let mut client = client::start(
        client_tun,
        client::ClientOptions {
            addr,
            path_interfaces: Vec::new(),
            server_name: "localhost".into(),
            client_config: client_cfg,
            // Keepalives/probes parked so every counter below is attributable
            // to the bonding batch; duplication disabled so the scheduler's
            // distribution is the only uplink traffic (phase 3, spec 12).
            keepalive_interval: Duration::from_secs(3600),
            probe_interval: Duration::from_secs(3600),
            probe_timeout: Duration::from_secs(3600),
            probe_failure_threshold: 2,
            redundancy_loss_threshold: 0.0,
        },
        session,
        &[PathId::new(1), PathId::new(2)],
        &token,
        None,
    )
    .await
    .unwrap();
    sleep(Duration::from_millis(150)).await;

    // Both paths healthy but asymmetric: path 1 is fast/clean/high-capacity,
    // path 2 is slower and lossier. Both stay under the 20% eligibility
    // cliff, so the phase-3 scheduler bonds them with a lopsided weight
    // ratio instead of failing path 2 over (spec 12 Phase 3).
    let p1 = PathId::new(1);
    let p2 = PathId::new(2);
    client
        .set_metrics(
            p1,
            PathMetrics {
                reachable: true,
                srtt_ms: 20,
                loss: 0.01,
                available_kbps: 50_000,
                ..Default::default()
            },
        )
        .await;
    client
        .set_metrics(
            p2,
            PathMetrics {
                reachable: true,
                srtt_ms: 90,
                loss: 0.10,
                available_kbps: 4_000,
                ..Default::default()
            },
        )
        .await;

    // Inject a batch of host frames; each gets its own sequence from the
    // shared per-session sequencer (seq 0..N regardless of path) and the
    // scheduler spreads them across both eligible paths by weight.
    let n: usize = 12;
    for i in 0..n {
        let id = 0x1001u16 + i as u16;
        client
            .tun
            .lock()
            .await
            .enqueue(Bytes::from(icmp_request([10, 0, 85, 2], [8, 8, 8, 8], id)));
    }

    // The whole batch must round-trip: requests forwarded to the host TUN in
    // order (gateway reorder window holds the interleaved arrivals, spec
    // 11.2), replies routed back on the active path.
    let mut delivered = false;
    for _ in 0..100 {
        if client.counters().await.frames_to_host as usize == n {
            delivered = true;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(delivered, "all {n} replies delivered to the client TUN");

    let cc = client.counters().await;
    assert_eq!(cc.datagrams_to_gateway as usize, n, "no duplicates, no lost frames");
    let d1 = *cc.uplink.get(&p1).unwrap_or(&0);
    let d2 = *cc.uplink.get(&p2).unwrap_or(&0);
    assert_eq!(d1 + d2, n as u64, "every frame is accounted for on a path");
    assert!(d1 > 0 && d2 > 0, "bonding spread the batch across BOTH paths (p1={d1}, p2={d2})");
    assert!(d1 > d2, "the faster path carries the larger share (p1={d1}, p2={d2})");
    let ratio12 = d1 as f32 / d2 as f32;
    assert!(
        (1.2..=3.5).contains(&ratio12),
        "share ratio {ratio12} is proportional to the ~2.4:1 weight ratio (p1={d1}, p2={d2})"
    );

    // Reorder contract: the interleaved arrival is reassembled with no drops.
    assert_eq!(cc.duplicates_dropped, 0, "client reorder window saw no drop");
    std::thread::sleep(Duration::from_millis(100));
    let gwc = gw.counters().await;
    assert_eq!(gwc.frames_to_host as usize, n, "gateway forwarded every frame in order");
    assert_eq!(gwc.duplicates_dropped, 0, "gateway reorder window saw no drop");

    let frames = client.tun.lock().await.drain_outbound();
    assert_eq!(
        frames.len(),
        n,
        "all {n} echoed replies are in the client TUN"
    );

    client.stop().await;
    gw.stop().await;
    host_task.abort();
}

/// Spec 12 Phase 3 DOWNLINK mirror: the client owns the authoritative
/// health snapshot and *advertises* the normalized per-path weights; the
/// gateway adopts the `Control::WeightSet` and spreads its downlink egress
/// with the same smooth-WRR scheduler the client's uplink uses.
///
/// Asymmetric weights across two healthy paths, N host replies: every reply
/// is sequenced by the shared per-session sequencer and distributed across
/// both paths proportional to weight, the client's reorder window
/// reassembles the interleaved arrivals in order with zero drops, and the
/// single-path active/standby fallback stays regression-free.
#[tokio::test]
async fn gateway_bonds_downlink_across_two_paths_by_advertised_weight() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    let secret = b"downlink-bonding-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut gw = tunnel::start(host_tun, gateway, secret.clone()).await;
    let host_task = tokio::spawn(host_echo(gw.tun.clone()));

    let client_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-lan0".into(),
        address: "10.0.85.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let session = session_id_from_wire(0xd0d0d0d0);
    let token = sg_auth::issue(&secret, session, 3600);
    let mut client = client::start(
        client_tun,
        client::ClientOptions {
            addr,
            path_interfaces: Vec::new(),
            server_name: "localhost".into(),
            client_config: client_cfg,
            // Keepalives/probes parked so every counter below is attributable
            // to the bonding batch; duplication disabled so the scheduler's
            // distribution is the only traffic on the wire.
            keepalive_interval: Duration::from_secs(3600),
            probe_interval: Duration::from_secs(3600),
            probe_timeout: Duration::from_secs(3600),
            probe_failure_threshold: 2,
            redundancy_loss_threshold: 0.0,
        },
        session,
        &[PathId::new(1), PathId::new(2)],
        &token,
        None,
    )
    .await
    .unwrap();
    sleep(Duration::from_millis(150)).await;

    // Both paths healthy but asymmetric (same picture as the uplink bonding
    // test): path 1 is fast/clean/high-capacity, path 2 slower and lossier.
    // Both stay under the 20% eligibility cliff, so the phase-3 weights stay
    // lopsided (~2.3:1) instead of collapsing to a single path.
    let p1 = PathId::new(1);
    let p2 = PathId::new(2);
    client
        .set_metrics(
            p1,
            PathMetrics {
                reachable: true,
                srtt_ms: 20,
                loss: 0.01,
                available_kbps: 50_000,
                ..Default::default()
            },
        )
        .await;
    client
        .set_metrics(
            p2,
            PathMetrics {
                reachable: true,
                srtt_ms: 90,
                loss: 0.10,
                available_kbps: 4_000,
                ..Default::default()
            },
        )
        .await;

    // A batch of host frames. Each leaves the client with its own sequence
    // (uplink spread by weight), is echoed by the host, and each reply gets
    // its OWN downlink sequence plus an egress path from the ADVERTISED
    // weights (spec 11.2: one per-session sequencer regardless of path).
    let n: usize = 16;
    for i in 0..n {
        let id = 0x2001u16 + i as u16;
        client
            .tun
            .lock()
            .await
            .enqueue(Bytes::from(icmp_request([10, 0, 85, 2], [8, 8, 8, 8], id)));
    }

    // Every reply must round-trip through the bonded downlink: the client's
    // reorder window reassembles the interleaved arrivals in sequence order.
    let mut delivered = false;
    for _ in 0..150 {
        if client.counters().await.frames_to_host as usize == n {
            delivered = true;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(delivered, "all {n} replies delivered to the client TUN");

    let cc = client.counters().await;
    assert_eq!(
        cc.datagrams_to_gateway as usize,
        n,
        "no duplicates, no lost requests"
    );
    assert_eq!(cc.duplicates_dropped, 0, "client reorder window saw no drop");
    assert!(
        cc.weight_sets >= 1,
        "the client advertised the phase-3 downlink weights"
    );

    let gwc = gw.counters().await;
    assert_eq!(
        gwc.frames_to_host as usize,
        n,
        "gateway forwarded every request in order"
    );
    assert_eq!(
        gwc.datagrams_to_client as usize,
        n,
        "gateway sent every reply"
    );
    assert_eq!(gwc.duplicates_dropped, 0, "gateway reorder window saw no drop");
    assert!(
        gwc.weight_sets >= 1,
        "the gateway adopted the advertised weights"
    );

    // The bonding egress proof: the per-path `downlink` counter shows the
    // spread, proportional to the advertised weight ratio.
    let d1 = *gwc.downlink.get(&p1).unwrap_or(&0);
    let d2 = *gwc.downlink.get(&p2).unwrap_or(&0);
    assert_eq!(d1 + d2, n as u64, "every reply is accounted for on a path");
    assert!(
        d1 > 0 && d2 > 0,
        "downlink bonding spread replies across BOTH paths (p1={d1}, p2={d2})"
    );
    assert!(d1 > d2, "the faster path carries the larger share (p1={d1}, p2={d2})");
    let ratio12 = d1 as f32 / d2 as f32;
    assert!(
        (1.2..=3.5).contains(&ratio12),
        "downlink share ratio {ratio12} tracks the ~2.3:1 weight ratio (p1={d1}, p2={d2})"
    );

    let frames = client.tun.lock().await.drain_outbound();
    assert_eq!(
        frames.len(),
        n,
        "all {n} echoed replies are in the client TUN"
    );

    client.stop().await;
    gw.stop().await;
    host_task.abort();
}