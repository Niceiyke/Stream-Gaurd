//! Rev1 path control over real QUIC (step 7 polish).
//!
//! The gateway serves a session's downlink on its own first-bound path;
//! `Control::PathSelect` lets the client move that downlink to another
//! bound path, so a client-side failover also redirects the reply traffic.

use bytes::Bytes;
use sg_core::PathId;
use sg_protocol::control::ControlMsg;
use sg_protocol::{Envelope, PacketType, VERSION};
use sg_session::session_id_from_wire;
use sg_transport::PathTransport;
use sg_transport::quic::{GatewayQuic, bootstrap_v1, client_tls, connect_path, server_tls};
use sg_tun::{LoopbackTun, TunConfig};
use streamguard_gateway::tunnel::start;
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

#[tokio::test]
async fn path_select_steers_downlink_to_the_new_active_path() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    let secret = b"path-control-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut handle = start(host_tun, gateway, secret.clone()).await;

    let session = session_id_from_wire(0xa1a2a3a4);
    let token = sg_auth::issue(&secret, session, 60);
    let a1 = PathId::new(1);
    let a2 = PathId::new(2);

    let ca1 = connect_path(addr, "localhost", client_cfg.clone(), a1).await.unwrap();
    bootstrap_v1(&ca1, session, &token).await.unwrap();
    let ca2 = connect_path(addr, "localhost", client_cfg.clone(), a2).await.unwrap();
    bootstrap_v1(&ca2, session, &token).await.unwrap();
    sleep(Duration::from_millis(100)).await; // accept + bind

    // ---- downlink round-trip 1 on the gateway's initial active path (a1) ----
    let request = icmp_request([10, 0, 85, 2], [8, 8, 8, 8], 0x1111);
    ca1.send(Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: a1,
        session_id: session,
        sequence: sg_core::Sequence::new(0),
        timestamp_ms: 0,
        payload: Bytes::copy_from_slice(&request),
    })
    .await
    .unwrap();
    sleep(Duration::from_millis(100)).await; // learn the flow
    let reply = icmp_reply([10, 0, 85, 2], [8, 8, 8, 8], 0x1111);
    handle
        .tun
        .lock()
        .await
        .enqueue(Bytes::from(reply.clone()));
    let r1 = ca1.recv().await.unwrap();
    assert_eq!(r1.path_id, a1, "reply 1 uses the first-bound active path");
    assert_eq!(r1.payload, Bytes::from(reply.clone()));
    assert_eq!(handle.counters().await.datagrams_to_client, 1);

    // ---- client failover: PathSelect { path: 2 } on the standby connection ----
    ca2.send(Envelope {
        version: VERSION,
        packet_type: PacketType::Control,
        flags: 0,
        path_id: a2,
        session_id: session,
        sequence: sg_core::Sequence::new(0),
        timestamp_ms: 0,
        payload: ControlMsg::PathSelect { path: a2.get() }
            .encode()
            .unwrap(),
    })
    .await
    .unwrap();
    sleep(Duration::from_millis(100)).await; // let the reader apply it
    assert_eq!(
        handle.counters().await.path_selects,
        1,
        "the gateway moved the session's active path"
    );

    // ---- a second reply for the same flow now exits path 2, and path 1 stays quiet ----
    handle
        .tun
        .lock()
        .await
        .enqueue(Bytes::from(reply.clone()));
    let r2 = ca2.recv().await.unwrap();
    assert_eq!(r2.path_id, a2, "reply 2 follows the steered active path");
    assert_eq!(r2.payload, Bytes::from(reply));
    assert_eq!(handle.counters().await.datagrams_to_client, 2);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), ca1.recv())
            .await
            .is_err(),
        "the old active path carries no further downlink after the switch"
    );

    handle.stop().await;
}

/// Spec 11.2 / 12: a `Duplicate` envelope carries the same sequence as an
/// earlier `Data` (phase 2 adaptive redundancy), and the gateway's reorder
/// window delivers only the first copy up the stack.
#[tokio::test]
async fn duplicate_seq_is_deduplicated_at_the_gateway() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    let secret = b"dedup-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut handle = start(host_tun, gateway, secret.clone()).await;

    let session = session_id_from_wire(0xd0dd12ab);
    let token = sg_auth::issue(&secret, session, 60);
    let a1 = PathId::new(1);
    let a2 = PathId::new(2);

    let ca1 = connect_path(addr, "localhost", client_cfg.clone(), a1).await.unwrap();
    bootstrap_v1(&ca1, session, &token).await.unwrap();
    let ca2 = connect_path(addr, "localhost", client_cfg.clone(), a2).await.unwrap();
    bootstrap_v1(&ca2, session, &token).await.unwrap();
    sleep(Duration::from_millis(100)).await; // accept + bind

    let seq = sg_core::Sequence::new(77);
    let payload = Bytes::from(icmp_request([10, 0, 85, 2], [8, 8, 8, 8], 0x2222));
    ca1.send(Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: a1,
        session_id: session,
        sequence: seq,
        timestamp_ms: 0,
        payload: payload.clone(),
    })
    .await
    .unwrap();
    // The redundant copy arrives on the other path with the same sequence;
    // whichever arrives first wins and the second is dropped.
    ca2.send(Envelope {
        version: VERSION,
        packet_type: PacketType::Duplicate,
        flags: 0,
        path_id: a2,
        session_id: session,
        sequence: seq,
        timestamp_ms: 0,
        payload,
    })
    .await
    .unwrap();
    sleep(Duration::from_millis(100)).await; // let both readers run

    let c = handle.counters().await;
    assert_eq!(c.frames_to_host, 1, "only the first copy reaches the host");
    assert_eq!(
        c.duplicates_dropped, 1,
        "the second copy is rejected by the reorder window"
    );

    handle.stop().await;
}

/// Spec 31.3: the gateway answers a per-path health probe with a `PathStatus`
/// reply echoing the probe id, so the client can measure RTT and detect a path
/// that has gone silent (soft failure) even while its QUIC connection lives.
#[tokio::test]
async fn probe_gets_echoed_back_as_path_status() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    let secret = b"probe-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut handle = start(host_tun, gateway, secret.clone()).await;

    let session = session_id_from_wire(0xc0de1234);
    let token = sg_auth::issue(&secret, session, 60);
    let a1 = PathId::new(1);

    let ca1 = connect_path(addr, "localhost", client_cfg.clone(), a1).await.unwrap();
    bootstrap_v1(&ca1, session, &token).await.unwrap();
    sleep(Duration::from_millis(100)).await; // accept + bind

    let probe_id = 0x0000_0042u32;
    ca1.send(Envelope {
        version: VERSION,
        packet_type: PacketType::Probe,
        flags: 0,
        path_id: a1,
        session_id: session,
        sequence: sg_core::Sequence::new(0),
        timestamp_ms: 0,
        payload: Bytes::copy_from_slice(&probe_id.to_be_bytes()),
    })
    .await
    .unwrap();

    let status = ca1
        .recv()
        .await
        .expect("the probe is answered with a PathStatus");
    assert_eq!(status.packet_type, PacketType::PathStatus);
    assert_eq!(status.path_id, a1, "reply stays on the probed path");
    assert_eq!(status.payload, Bytes::from(probe_id.to_be_bytes().to_vec()));
    assert_eq!(
        handle.counters().await.probes_replied,
        1,
        "one probe answered"
    );

    handle.stop().await;
}