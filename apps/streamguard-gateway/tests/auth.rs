//! Gateway bootstrap auth (engineering step 8): a connection must present a
//! gateway-signed session ticket before it can carry data. A bad or
//! mismatched ticket is Nacked and dropped; a valid ticket accredits the
//! path for exactly the session the ticket names.

use bytes::Bytes;
use sg_core::PathId;
use sg_protocol::{Envelope, PacketType, VERSION};
use sg_session::session_id_from_wire;
use sg_transport::quic::{GatewayQuic, bootstrap_v1, client_tls, connect_path, server_tls};
use sg_transport::PathTransport;
use sg_tun::{LoopbackTun, TunConfig};
use streamguard_gateway::tunnel::start;
use tokio::time::{sleep, Duration};

/// Builds a self-signed gateway pair and returns (gateway, secret, cert_der).
fn gw_pair(secret: &'static [u8]) -> (GatewayQuic, Vec<u8>, Vec<u8>) {
    let (cert_der, key_der) = {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    };
    let server_cfg = server_tls(&cert_der, &key_der).unwrap();
    let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
    (gateway, secret.to_vec(), cert_der)
}

fn make_client_cfg(cert_der: &[u8]) -> quinn::ClientConfig {
    client_tls(cert_der).unwrap()
}

fn icmp_request(src: [u8; 4], dst: [u8; 4], echo_id: u16) -> Vec<u8> {
    let mut v = vec![
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, src[0], src[1],
        src[2], src[3], dst[0], dst[1], dst[2], dst[3],
    ];
    let mut icmp = vec![0x08, 0x00, 0x00, 0x00];
    icmp.extend_from_slice(&echo_id.to_be_bytes());
    icmp.extend_from_slice(&[0x00, 0x01]);
    v.extend_from_slice(&icmp);
    v
}

#[tokio::test]
async fn bad_ticket_is_nacked_and_never_forms_a_session() {
    let secret: &'static [u8] = b"auth-test-secret";
    let (gateway, secret_vec, cert) = gw_pair(secret);
    let addr = gateway.local_addr().unwrap();

    let mut handle = start(LoopbackTun::with_config(TunConfig::default()), gateway, secret_vec).await;

    let session = session_id_from_wire(0x11111111);
    let path = PathId::new(1);
    let client = connect_path(addr, "localhost", make_client_cfg(&cert), path)
        .await
        .unwrap();

    // Ticket signed with a different secret → gateway must refuse.
    let wrong = sg_auth::issue(b"not-the-secret", session, 60);
    assert!(bootstrap_v1(&client, session, &wrong).await.is_err());
    sleep(Duration::from_millis(100)).await;

    let c = handle.counters().await;
    assert_eq!(c.auth_rejections, 1);
    assert_eq!(c.paths, 0, "rejected connection is not accredited");
    assert_eq!(c.sessions, 0, "no session formed without valid auth");

    handle.stop().await;
}

#[tokio::test]
async fn mismatched_session_in_ticket_is_rejected() {
    let secret: &'static [u8] = b"auth-test-secret";
    let (gateway, secret_vec, cert) = gw_pair(secret);
    let addr = gateway.local_addr().unwrap();

    let mut handle = start(LoopbackTun::with_config(TunConfig::default()), gateway, secret_vec).await;

    let claimed = session_id_from_wire(0x22222222);
    let other = session_id_from_wire(0x33333333);
    let path = PathId::new(1);
    let client = connect_path(addr, "localhost", make_client_cfg(&cert), path)
        .await
        .unwrap();

    // Valid signature but the ticket names a different session than the one
    // the client claims on the wire.
    let token = sg_auth::issue(secret, other, 60);
    assert!(bootstrap_v1(&client, claimed, &token).await.is_err());
    sleep(Duration::from_millis(100)).await;

    let c = handle.counters().await;
    assert_eq!(c.auth_rejections, 1);
    assert_eq!(c.sessions, 0);

    handle.stop().await;
}

#[tokio::test]
async fn valid_ticket_accredits_two_paths_for_one_session() {
    let secret: &'static [u8] = b"auth-test-secret";
    let (gateway, secret_vec, cert) = gw_pair(secret);
    let addr = gateway.local_addr().unwrap();

    let mut handle = start(LoopbackTun::with_config(TunConfig::default()), gateway, secret_vec).await;

    let session = session_id_from_wire(0x44444444);
    let token = sg_auth::issue(secret, session, 60);
    let cfg = make_client_cfg(&cert);

    // Both paths bootstrap with the same signed ticket.
    let p1 = connect_path(addr, "localhost", cfg.clone(), PathId::new(1))
        .await
        .unwrap();
    bootstrap_v1(&p1, session, &token).await.unwrap();
    let p2 = connect_path(addr, "localhost", cfg, PathId::new(2))
        .await
        .unwrap();
    bootstrap_v1(&p2, session, &token).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    // Connections are accredited: both paths are bound to the session at
    // authentication time (spec 15 "associate multiple paths with a
    // session"), so a standby path is visible and evictable gateway-side
    // even before it ever carries traffic (spec 12 phase 1).
    assert_eq!(handle.counters().await.paths, 2);
    assert_eq!(handle.counters().await.auth_rejections, 0);
    assert_eq!(handle.counters().await.sessions, 1);

    // First data frame (on p1) hits the host TUN.
    let pkt = icmp_request([10, 0, 85, 2], [8, 8, 8, 8], 0x5555);
    p1.send(Envelope {
        version: VERSION,
        packet_type: PacketType::Data,
        flags: 0,
        path_id: PathId::new(1),
        session_id: session,
        sequence: sg_core::Sequence::new(0),
        timestamp_ms: 0,
        payload: Bytes::from(pkt),
    })
    .await
    .unwrap();
    sleep(Duration::from_millis(100)).await;

    let c = handle.counters().await;
    assert_eq!(c.sessions, 1, "both paths accredit the one wire session");
    assert_eq!(c.frames_to_host, 1);
    assert_eq!(handle.tun.lock().await.drain_outbound().len(), 1);

    handle.stop().await;
    eprintln!("A: stopped");
}
