//! Multi-session, multi-path gateway test over real QUIC (step 5).
//!
//! Two logical sessions, each with two physical QUIC paths, share a single
//! gateway TUN. The engine demultiplexes sessions, learns flows, and
//! routes replies back to the originating session's active path. Also
//! proves the uplink reorder window rejects a genuine on-the-wire
//! duplicate.

use bytes::Bytes;
use sg_core::PathId;
use sg_session::session_id_from_wire;
use sg_protocol::{Envelope, PacketType, VERSION};
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
async fn two_sessions_two_paths_share_one_gateway_tun() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    // One gateway TUN for all sessions.
    let secret = b"multisession-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut handle = start(host_tun, gateway, secret.clone()).await;

    // Two sessions, two paths each. Every connection must bootstrap with the
    // signed ticket for its session before it can carry data.
    let session_a = session_id_from_wire(0xa0a0a0a0);
    let session_b = session_id_from_wire(0xb0b0b0b0);
    let token_a = sg_auth::issue(&secret, session_a, 60);
    let token_b = sg_auth::issue(&secret, session_b, 60);
    let a1 = PathId::new(1);
    let a2 = PathId::new(2);
    let b1 = PathId::new(3);
    let b2 = PathId::new(4);

    let ca1 = connect_path(addr, "localhost", client_cfg.clone(), a1).await.unwrap();
    bootstrap_v1(&ca1, session_a, &token_a).await.unwrap();
    let ca2 = connect_path(addr, "localhost", client_cfg.clone(), a2).await.unwrap();
    bootstrap_v1(&ca2, session_a, &token_a).await.unwrap();
    let cb1 = connect_path(addr, "localhost", client_cfg.clone(), b1).await.unwrap();
    bootstrap_v1(&cb1, session_b, &token_b).await.unwrap();
    let cb2 = connect_path(addr, "localhost", client_cfg.clone(), b2).await.unwrap();
    bootstrap_v1(&cb2, session_b, &token_b).await.unwrap();
    sleep(Duration::from_millis(100)).await; // let the engine finish accepting/binding
    let _ = (&ca2, &cb2); // standby paths exist but are idle in phase 1

    // Session A, path A1: client → gateway request.
    let a_request = icmp_request([10, 0, 85, 2], [8, 8, 8, 8], 0x1111);
    let env_a = Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: a1,
        session_id: session_a,
        sequence: sg_core::Sequence::new(0),
        timestamp_ms: 0,
        payload: Bytes::copy_from_slice(&a_request),
    };
    ca1.send(env_a).await.unwrap();

    // Session B, path B1: a second, independent session.
    let b_request = icmp_request([10, 0, 85, 3], [1, 1, 1, 1], 0x2222);
    let env_b = Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: b1,
        session_id: session_b,
        sequence: sg_core::Sequence::new(0),
        timestamp_ms: 0,
        payload: Bytes::copy_from_slice(&b_request),
    };
    cb1.send(env_b).await.unwrap();

    // Let the readers forward both to the host TUN.
    sleep(Duration::from_millis(100)).await;
    let outbound = handle.tun.lock().await.drain_outbound();
    assert_eq!(outbound.len(), 2, "both sessions' requests reach the host TUN");
    assert!(outbound.contains(&Bytes::from(a_request.clone())));
    assert!(outbound.contains(&Bytes::from(b_request.clone())));
    assert_eq!(handle.counters().await.frames_to_host, 2);

    // ---- downlink: host replies, routed back per-session ----
    // A reply to A comes from 8.8.8.8 to 10.0.85.2 echo 0x1111; the engine
    // reverses the flow and must send it back to session A.
    let a_reply = icmp_reply([10, 0, 85, 2], [8, 8, 8, 8], 0x1111);
    handle
        .tun
        .lock()
        .await
        .enqueue(Bytes::from(a_reply.clone()));
    // A reply to B comes from 1.1.1.1 to 10.0.85.3 echo 0x2222.
    let b_reply = icmp_reply([10, 0, 85, 3], [1, 1, 1, 1], 0x2222);
    handle
        .tun
        .lock()
        .await
        .enqueue(Bytes::from(b_reply.clone()));

    // Session A receives its reply on its ACTIVE path (A1 = first bound).
    let a_recv = ca1.recv().await.unwrap();
    assert_eq!(a_recv.path_id, a1);
    assert_eq!(a_recv.payload, Bytes::from(a_reply.clone()));

    // Session B receives its reply on B1 (its active path).
    let b_recv = cb1.recv().await.unwrap();
    assert_eq!(b_recv.path_id, b1);
    assert_eq!(b_recv.payload, Bytes::from(b_reply.clone()));
    assert_eq!(handle.counters().await.datagrams_to_client, 2);

    handle.stop().await;
}

#[tokio::test]
async fn uplink_rejects_on_wire_duplicate() {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    let secret = b"duplicate-test-secret".to_vec();
    let host_tun = LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    });
    let mut handle = start(host_tun, gateway, secret.clone()).await;

    let session = session_id_from_wire(0xc0c0c0c0);
    let token = sg_auth::issue(&secret, session, 60);
    let path = PathId::new(1);
    let client = connect_path(addr, "localhost", client_cfg, path).await.unwrap();
    bootstrap_v1(&client, session, &token).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    let pkt = icmp_request([10, 0, 85, 2], [8, 8, 8, 8], 0x3333);
    let make = |seq: u64| Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: path,
        session_id: session,
        sequence: sg_core::Sequence::new(seq),
        timestamp_ms: 0,
        payload: Bytes::copy_from_slice(&pkt),
    };
    // Send the same sequence twice over the wire.
    client.send(make(0)).await.unwrap();
    client.send(make(0).clone()).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    // Only the first copy is forwarded to the host TUN.
    let c = handle.counters().await;
    assert_eq!(c.frames_to_host, 1);
    assert_eq!(c.duplicates_dropped, 1);
    assert_eq!(handle.tun.lock().await.drain_outbound().len(), 1);

    handle.stop().await;
}
