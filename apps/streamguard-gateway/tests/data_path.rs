//! End-to-end logical tunnel over real QUIC connections (engineering
//! milestone "stable single-path tunnel" lifted onto `sg-transport::quic`).
//!
//! The wire is now a genuine encrypted QUIC connection per path instead of
//! the in-process buffer the first milestone used. TUN endpoints stay
//! loopback so the test runs without elevation; every envelope travels
//! client -> quinn gateway -> TUN, and the skin over QUIC datagrams is the
//! same `PathTransport` the scheduler will drive.

use bytes::Bytes;
use sg_core::{PathId, SessionId};
use sg_multipath::{Sequencer, default_reorder_window};
use sg_protocol::{Envelope, PacketType, VERSION};
use sg_transport::PathTransport;
use sg_transport::quic::{GatewayQuic, client_tls, connect_path, server_tls};
use sg_tun::{LoopbackTun, Tun, TunConfig};

/// Minimal IPv4 header + ICMP echo request from the client (10.0.85.2).
fn icmp_request() -> Vec<u8> {
    let mut v = vec![
        0x45, 0x00, 0x00, 0x1c, // IP version/length
        0x00, 0x00, 0x00, 0x00, // id/flags/frag
        0x40, 0x01, 0x00, 0x00, // ttl/proto=ICMP/checksum
        10, 0, 85, 2, // src 10.0.85.2
        8, 8, 8, 8, // dst 8.8.8.8
    ];
    v.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00]);
    v
}

/// Matching ICMP echo reply: 8.8.8.8 -> 10.0.85.2.
fn icmp_reply() -> Vec<u8> {
    let mut v = vec![
        0x45, 0x00, 0x00, 0x1c, //
        0x00, 0x00, 0x00, 0x00, //
        0x40, 0x01, 0x00, 0x00, //
        8, 8, 8, 8, // src 8.8.8.8
        10, 0, 85, 2, // dst 10.0.85.2
    ];
    v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00]);
    v
}

fn client_tun() -> LoopbackTun {
    LoopbackTun::with_config(TunConfig::default())
}

fn gateway_tun() -> LoopbackTun {
    LoopbackTun::with_config(TunConfig {
        name: "sg-wan0".into(),
        address: "192.168.1.1".into(),
        prefix_len: 24,
        mtu: 1300,
    })
}

fn self_signed(server_name: &str) -> (Vec<u8>, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(vec![server_name.into()])
        .expect("rcgen self-signed cert");
    (certified.cert.der().to_vec(), certified.key_pair.serialize_der())
}

#[tokio::test]
async fn client_forward_and_return_round_trip_two_paths() {
    let (cert_der, key_der) = self_signed("localhost");
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let client_cfg = client_tls(&cert_der).unwrap();

    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    let addr = gateway.local_addr().unwrap();

    let session = SessionId::new();
    let path_a = PathId::new(1);
    let path_b = PathId::new(2);
    let request = icmp_request();
    let reply = icmp_reply();

    // Gateway side: accept the uplink and downlink paths as QUIC
    // connections, then hand the transports back to this task.
    let accept_paths = {
        let gateway = gateway.clone();
        tokio::spawn(async move {
            let uplink_path = gateway.accept(path_a).await.unwrap();
            let downlink_path = gateway.accept(path_b).await.unwrap();
            (uplink_path, downlink_path)
        })
    };

    // Client side: one real QUIC connection per physical path.
    let client_uplink = connect_path(addr, "localhost", client_cfg.clone(), path_a)
        .await
        .unwrap();
    let client_downlink = connect_path(addr, "localhost", client_cfg, path_b)
        .await
        .unwrap();
    let (gw_uplink, gw_downlink) = accept_paths.await.unwrap();

    let mut client_tun = client_tun();
    let mut gateway_tun = gateway_tun();
    let mut client_seq = Sequencer::new();
    let mut gw_seq = Sequencer::new();
    // Uplink and downlink use independent sequence spaces and windows.
    let mut uplink = default_reorder_window();
    let mut downlink = default_reorder_window();

    // ---- uplink: client reads packet from TUN, sends it over QUIC path A ----
    client_tun.enqueue(Bytes::from(request.clone()));
    let mut buf = [0u8; 1300];
    let n = client_tun.read(&mut buf).unwrap();
    assert_eq!(n, request.len());
    assert_eq!(&buf[..n], &request[..]);

    let seq_client = client_seq.next_sequence();
    let uplink_env = Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: path_a,
        session_id: session,
        sequence: seq_client,
        timestamp_ms: 0,
        payload: Bytes::copy_from_slice(&buf[..n]),
    };
    client_uplink.send(uplink_env).await.unwrap();

    // gateway: receive over QUIC path A, reorder/dedup, inject into TUN
    let decoded = gw_uplink.recv().await.unwrap();
    assert_eq!(decoded.version, VERSION);
    assert_eq!(decoded.packet_type, PacketType::Data);
    assert_eq!(decoded.path_id, path_a);
    assert_eq!(decoded.sequence, seq_client);
    assert!(uplink.accept(decoded.sequence));
    assert!(!uplink.accept(decoded.sequence), "duplicate rejected");

    let written = gateway_tun.write(&decoded.payload).unwrap();
    assert_eq!(written, request.len());
    assert_eq!(
        gateway_tun.drain_outbound(),
        vec![Bytes::from(request.clone())]
    );

    // ---- downlink: reply leaves the gateway TUN, over QUIC path B ----
    gateway_tun.enqueue(Bytes::from(reply.clone()));
    let n = gateway_tun.read(&mut buf).unwrap();
    assert_eq!(n, reply.len());
    assert_eq!(&buf[..n], &reply[..]);

    let seq_gw = gw_seq.next_sequence();
    let downlink_env = Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: path_b,
        session_id: session,
        sequence: seq_gw,
        timestamp_ms: 0,
        payload: Bytes::copy_from_slice(&buf[..n]),
    };
    gw_downlink.send(downlink_env).await.unwrap();

    // client: receive over QUIC path B and unwrap into the client TUN
    let decoded_reply = client_downlink.recv().await.unwrap();
    assert_eq!(decoded_reply.path_id, path_b);
    assert!(downlink.accept(decoded_reply.sequence));
    assert!(!downlink.accept(decoded_reply.sequence), "duplicate rejected");

    client_tun.write(&decoded_reply.payload).unwrap();
    assert_eq!(
        client_tun.drain_outbound(),
        vec![Bytes::from(reply.clone())]
    );
}