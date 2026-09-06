//! End-to-end logical tunnel proof over in-memory TUNs (engineering
//! milestone "stable single-path tunnel").
//!
//! Exercises the full gateway/client plumbing that a real QUIC transport
//! will later carry: client TUN read -> envelope encode -> (wire) ->
//! envelope decode -> reorder/dedup -> gateway TUN write, then the
//! reverse direction on a second path.

use bytes::{Bytes, BytesMut};
use sg_core::{PathId, SessionId};
use sg_multipath::{Sequencer, default_reorder_window};
use sg_protocol::{Envelope, PacketType, VERSION};
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

#[test]
fn client_forward_and_return_round_trip_two_paths() {
    let session = SessionId::new();
    let path_a = PathId::new(1);
    let path_b = PathId::new(2);
    let request = icmp_request();
    let reply = icmp_reply();

    let mut client_tun = client_tun();
    let mut gateway_tun = gateway_tun();
    let mut client_seq = Sequencer::new();
    let mut gw_seq = Sequencer::new();
    // Uplink and downlink use independent sequence spaces and windows.
    let mut uplink = default_reorder_window();
    let mut downlink = default_reorder_window();
    let mut wire_buf = BytesMut::with_capacity(2048);

    // ---- uplink: client writes packet into TUN, engine wraps it ----
    client_tun.enqueue(Bytes::from(request.clone()));
    let mut buf = [0u8; 1300];
    let n = client_tun.read(&mut buf).unwrap();
    assert_eq!(n, request.len());
    assert_eq!(&buf[..n], &request[..]);

    let seq_client = client_seq.next_sequence();
    Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: path_a,
        session_id: session,
        sequence: seq_client,
        timestamp_ms: 0,
        payload: Bytes::copy_from_slice(&buf[..n]),
    }
    .encode(&mut wire_buf)
    .unwrap();
    let mut wire = wire_buf.split().freeze();

    // gateway: decode, dedup, unwrap, inject into gateway TUN
    let decoded = Envelope::decode(&mut wire).unwrap();
    assert_eq!(decoded.version, VERSION);
    assert_eq!(decoded.packet_type, PacketType::Data);
    assert_eq!(decoded.path_id, path_a);
    assert_eq!(decoded.sequence, seq_client);
    assert!(uplink.accept(decoded.sequence));
    assert!(!uplink.accept(decoded.sequence), "duplicate rejected");

    let written = gateway_tun.write(&decoded.payload).unwrap();
    assert_eq!(written, request.len());
    assert_eq!(gateway_tun.drain_outbound(), vec![Bytes::from(request.clone())]);

    // ---- downlink: reply arrives on a second path through the gateway ----
    gateway_tun.enqueue(Bytes::from(reply.clone()));
    let n = gateway_tun.read(&mut buf).unwrap();
    assert_eq!(n, reply.len());
    assert_eq!(&buf[..n], &reply[..]);

    let seq_gw = gw_seq.next_sequence();
    Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: path_b,
        session_id: session,
        sequence: seq_gw,
        timestamp_ms: 0,
        payload: Bytes::copy_from_slice(&buf[..n]),
    }
    .encode(&mut wire_buf)
    .unwrap();
    let mut wire = wire_buf.split().freeze();

    let decoded_reply = Envelope::decode(&mut wire).unwrap();
    assert_eq!(decoded_reply.path_id, path_b);
    assert!(downlink.accept(decoded_reply.sequence));
    assert!(!downlink.accept(decoded_reply.sequence), "duplicate rejected");

    client_tun.write(&decoded_reply.payload).unwrap();
    assert_eq!(client_tun.drain_outbound(), vec![Bytes::from(reply.clone())]);
}