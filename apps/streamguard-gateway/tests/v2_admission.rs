//! Real-Quinn coverage for the isolated V2 control-admission listener.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivatePkcs8KeyDer};
use sg_auth::device::{
    DeviceCredential, DeviceCredentialError, DeviceTrustAnchors, GatewayName,
    GatewayTlsIdentity, GatewayTrustAnchors, VerifiedPeerDeviceIdentityExtractor,
};
use sg_auth::ticket::{ControllerPublicKey, ControllerTrustSnapshot, TicketVerifier};
use sg_core::v2::{DeviceId, SessionId};
use sg_protocol::v2::control::{
    AdmissionTicket, ControlFrame, ControlFrameLimit, ControlMessage, SafeModePolicy,
};
use sg_transport::quic::{v2_client_tls, v2_connect_path};
use sg_transport::v2::{ControlDeadlines, ControlFramed};
use streamguard_gateway::v2::admission::{
    AdmissionHandler, AdmissionTime,
    HandshakeAdmissionLimiter, HandshakeAdmissionLimiterConfig, ReplayCache,
};
use streamguard_gateway::v2::address_pool::{AddressPool, AddressPoolConfig};
use streamguard_gateway::v2::session_manager::{
    SessionCleanup, V2SessionManager, V2SessionManagerConfig,
};
use streamguard_gateway::v2::listener::{
    SessionAdmitTemplate, V2AdmissionListener, V2AdmissionListenerConfig,
    V2AdmissionListenerSetup, V2AdmissionTls,
};
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const FIXTURE_PUBLIC_KEY: &str = "kFjlN2-bMhd6GHDoZWSsAwQK8i82AeXe9G3lO9harE8";
const FIXTURE_TICKET: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImNvbnRyb2xsZXItMSJ9.eyJqdGkiOiIwMTAxMDEwMS0wMTAxLTAxMDEtMDEwMS0wMTAxMDEwMTAxMDEiLCJpc3MiOiJjb250cm9sbGVyLmV4YW1wbGUiLCJhdWQiOiJnYXRld2F5LWdyb3VwLWEiLCJkZXZpY2UiOiIwMjAyMDIwMi0wMjAyLTAyMDItMDIwMi0wMjAyMDIwMjAyMDIiLCJvcmdhbml6YXRpb24iOiIwMzAzMDMwMy0wMzAzLTAzMDMtMDMwMy0wMzAzMDMwMzAzMDMiLCJzZXNzaW9uIjoiMDQwNDA0MDQtMDQwNC0wNDA0LTA0MDQtMDQwNDA0MDQwNDA0IiwiaWF0Ijo5OTksImV4cCI6MTA2MCwicG9saWN5X3ZlcnNpb24iOjEsInJlZ2lvbnMiOlsidXMtZWFzdC0xIl0sIm5vbmNlIjoiMDUwNTA1MDUtMDUwNS0wNTA1LTA1MDUtMDUwNTA1MDUwNTA1In0.mnBkAfIsNBCLi_oEd6vD5SKvHedJwXYu5iuojafL_DRwx5MR2flRPLSQ0a6-ACQUWjWOPb-jOajIKj-RJZNjAQ";
const FIXTURE_SECOND_TICKET: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImNvbnRyb2xsZXItMSJ9.eyJqdGkiOiIwNjA2MDYwNi0wNjA2LTA2MDYtMDYwNi0wNjA2MDYwNjA2MDYiLCJpc3MiOiJjb250cm9sbGVyLmV4YW1wbGUiLCJhdWQiOiJnYXRld2F5LWdyb3VwLWEiLCJkZXZpY2UiOiIwMjAyMDIwMi0wMjAyLTAyMDItMDIwMi0wMjAyMDIwMjAyMDIiLCJvcmdhbml6YXRpb24iOiIwMzAzMDMwMy0wMzAzLTAzMDMtMDMwMy0wMzAzMDMwMzAzMDMiLCJzZXNzaW9uIjoiMDQwNDA0MDQtMDQwNC0wNDA0LTA0MDQtMDQwNDA0MDQwNDA0IiwiaWF0Ijo5OTksImV4cCI6MTA2MCwicG9saWN5X3ZlcnNpb24iOjEsInJlZ2lvbnMiOlsidXMtZWFzdC0xIl0sIm5vbmNlIjoiMDUwNTA1MDUtMDUwNS0wNTA1LTA1MDUtMDUwNTA1MDUwNTA1In0._ylL_STUNgBnHkQSV40YYQHgBPf0Mq6CqcBCX04TnCLBBKX3AyGJ7mlfUZ0XNKLu2zRduopJxTnrrpyTtjIJAw";
const FIXTURE_CONFLICT_TICKET: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImNvbnRyb2xsZXItMSJ9.eyJqdGkiOiIwNzA3MDcwNy0wNzA3LTA3MDctMDcwNy0wNzA3MDcwNzA3MDciLCJpc3MiOiJjb250cm9sbGVyLmV4YW1wbGUiLCJhdWQiOiJnYXRld2F5LWdyb3VwLWEiLCJkZXZpY2UiOiIwODA4MDgwOC0wODA4LTA4MDgtMDgwOC0wODA4MDgwODA4MDgiLCJvcmdhbml6YXRpb24iOiIwMzAzMDMwMy0wMzAzLTAzMDMtMDMwMy0wMzAzMDMwMzAzMDMiLCJzZXNzaW9uIjoiMDQwNDA0MDQtMDQwNC0wNDA0LTA0MDQtMDQwNDA0MDQwNDA0IiwiaWF0Ijo5OTksImV4cCI6MTA2MCwicG9saWN5X3ZlcnNpb24iOjEsInJlZ2lvbnMiOlsidXMtZWFzdC0xIl0sIm5vbmNlIjoiMDUwNTA1MDUtMDUwNS0wNTA1LTA1MDUtMDUwNTA1MDUwNTA1In0.rsyl_SD3rCMKynoTDc713eRjvL8sCnGlH804xxatsPJNDbmavqYcsGZbICc4FyMCBO4Ktaz2B1ZoMBM9fMEqAQ";

#[derive(Debug)]
struct ClientResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for ClientResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct NoClientResolver;

impl rustls::client::ResolvesClientCert for NoClientResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct TestCredential {
    device_id: DeviceId,
    resolver: Arc<dyn rustls::client::ResolvesClientCert>,
}

impl DeviceCredential for TestCredential {
    fn device_id(&self) -> DeviceId {
        self.device_id
    }

    fn client_cert_resolver(&self) -> Arc<dyn rustls::client::ResolvesClientCert> {
        Arc::clone(&self.resolver)
    }
}

#[derive(Debug)]
struct ServerResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for ServerResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[derive(Debug)]
struct TestGatewayIdentity(Arc<dyn rustls::server::ResolvesServerCert>);

impl GatewayTlsIdentity for TestGatewayIdentity {
    fn server_cert_resolver(&self) -> Arc<dyn rustls::server::ResolvesServerCert> {
        Arc::clone(&self.0)
    }
}

#[derive(Debug)]
struct ChainExtractor {
    certificate: CertificateDer<'static>,
    device_id: DeviceId,
    reject: bool,
}

impl VerifiedPeerDeviceIdentityExtractor for ChainExtractor {
    fn extract(&self, chain: &[CertificateDer<'_>]) -> Result<DeviceId, DeviceCredentialError> {
        if !self.reject && chain.first().is_some_and(|certificate| certificate.as_ref() == self.certificate.as_ref()) {
            Ok(self.device_id)
        } else {
            Err(DeviceCredentialError::PeerIdentityMismatch)
        }
    }
}

struct TestCa {
    certificate: Certificate,
    key: KeyPair,
}

fn certificate_authority(name: &str) -> TestCa {
    let mut params = CertificateParams::new(vec![name.into()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    TestCa { certificate, key }
}

fn signed_leaf(
    ca: &TestCa,
    dns_name: &str,
    usage: ExtendedKeyUsagePurpose,
    serial: u64,
) -> (CertificateDer<'static>, Vec<u8>) {
    let mut params = CertificateParams::new(vec![dns_name.into()]).unwrap();
    params.serial_number = Some(SerialNumber::from(serial));
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().unwrap();
    let certificate = params.signed_by(&key, &ca.certificate, &ca.key).unwrap();
    (certificate.der().clone(), key.serialize_der())
}

fn crl(ca: &TestCa) -> CertificateRevocationListDer<'static> {
    CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2025, 1, 1),
        next_update: rcgen::date_time_ymd(2030, 1, 1),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca.certificate, &ca.key)
    .unwrap()
    .into()
}

fn certified_key(certificate: CertificateDer<'static>, key: Vec<u8>) -> Arc<rustls::sign::CertifiedKey> {
    Arc::new(
        rustls::sign::CertifiedKey::from_der(
            vec![certificate],
            PrivatePkcs8KeyDer::from(key).into(),
            &rustls::crypto::ring::default_provider(),
        )
        .unwrap(),
    )
}

struct TestPki {
    gateway_identity: TestGatewayIdentity,
    gateway_trust: GatewayTrustAnchors,
    device_trust: DeviceTrustAnchors,
    credential: TestCredential,
    client_certificate: CertificateDer<'static>,
}

fn pki() -> TestPki {
    let gateway_ca = certificate_authority("gateway-ca.test");
    let device_ca = certificate_authority("device-ca.test");
    let (server_certificate, server_key) = signed_leaf(&gateway_ca, "localhost", ExtendedKeyUsagePurpose::ServerAuth, 10);
    let (client_certificate, client_key) = signed_leaf(&device_ca, "device.test", ExtendedKeyUsagePurpose::ClientAuth, 20);
    TestPki {
        gateway_identity: TestGatewayIdentity(Arc::new(ServerResolver(certified_key(server_certificate, server_key)))),
        gateway_trust: GatewayTrustAnchors::new(vec![gateway_ca.certificate.der().clone()], vec![crl(&gateway_ca)]).unwrap(),
        device_trust: DeviceTrustAnchors::new(vec![device_ca.certificate.der().clone()], vec![crl(&device_ca)]).unwrap(),
        credential: TestCredential {
            device_id: DeviceId::from_bytes([2; 16]),
            resolver: Arc::new(ClientResolver(certified_key(client_certificate.clone(), client_key))),
        },
        client_certificate,
    }
}

fn address_pool_config() -> AddressPoolConfig {
    AddressPoolConfig::new(
        [10, 64, 0, 0],
        24,
        [10, 64, 0, 1],
        vec![],
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        48,
        4,
        5_000,
        120_000,
        4,
    )
    .unwrap()
}

fn test_pool() -> Arc<AddressPool> {
    Arc::new(AddressPool::new(address_pool_config()).unwrap())
}

fn session_manager_with_pool(pool: &Arc<AddressPool>) -> Arc<V2SessionManager> {
    Arc::new(
        V2SessionManager::with_cleanup(
            V2SessionManagerConfig {
                maximum_sessions: 4,
                idle_ttl_ms: 120_000,
                maximum_paths_per_session: 4,
                maximum_pending_attaches: 4,
                pending_attach_ttl_ms: 5_000,
                maximum_path_epoch_history: 16,
                maximum_path_tombstones: 4,
                path_tombstone_ttl_ms: 5_000,
            },
            vec![Arc::clone(pool) as Arc<dyn SessionCleanup>],
        )
        .unwrap(),
    )
}

fn handler_with_sessions(
    sessions: Arc<V2SessionManager>,
) -> Arc<AdmissionHandler<TicketVerifier>> {
    Arc::new(AdmissionHandler::new(
        TicketVerifier::new("controller.example".into(), "gateway-group-a".into(), "us-east-1".into()).unwrap(),
        HandshakeAdmissionLimiter::new(HandshakeAdmissionLimiterConfig {
            source_capacity: 8,
            source_ttl_millis: 1_000,
            maximum_per_source_in_flight: 4,
            maximum_global_in_flight: 8,
            maximum_verification_budget_millis: 100,
        })
        .unwrap(),
        ReplayCache::new(8).unwrap(),
        sessions,
    ))
}

fn handler() -> (Arc<AdmissionHandler<TicketVerifier>>, Arc<AddressPool>) {
    let pool = test_pool();
    let sessions = session_manager_with_pool(&pool);
    (handler_with_sessions(sessions), pool)
}

fn trust() -> Arc<ControllerTrustSnapshot> {
    Arc::new(
        ControllerTrustSnapshot::new(
            vec![ControllerPublicKey::new("controller-1".into(), FIXTURE_PUBLIC_KEY.into()).unwrap()],
            vec![],
            1_001,
        )
        .unwrap(),
    )
}

fn listener_config() -> V2AdmissionListenerConfig {
    V2AdmissionListenerConfig {
        handshake_timeout: TEST_TIMEOUT,
        control_stream_timeout: TEST_TIMEOUT,
        control_deadlines: ControlDeadlines { read: TEST_TIMEOUT, write: TEST_TIMEOUT },
        control_frame_limit: ControlFrameLimit::default(),
    }
}

fn template() -> SessionAdmitTemplate {
    SessionAdmitTemplate::new(SafeModePolicy::new(Bytes::from_static(b"safe-mode")).unwrap())
}

fn hello(ticket: &str, device_id: DeviceId) -> ControlFrame {
    ControlFrame {
        transaction_id: 1,
        message: ControlMessage::ClientHello {
            device_id,
            requested_gateway: "gateway.example".into(),
            ticket: AdmissionTicket::new(ticket.into()).unwrap(),
        },
    }
}

async fn connect_and_send(
    address: std::net::SocketAddr,
    pki: &TestPki,
    frame: ControlFrame,
) -> (quinn::Connection, quinn::RecvStream) {
    let (client, mut send, recv) = connect_and_open(address, pki).await;
    send.write_frame(&frame).await.unwrap();
    (client, recv.into_inner())
}

async fn connect_and_open(
    address: std::net::SocketAddr,
    pki: &TestPki,
) -> (quinn::Connection, ControlFramed<quinn::SendStream>, ControlFramed<quinn::RecvStream>) {
    let client = v2_connect_path(
        address,
        &GatewayName::new("localhost").unwrap(),
        v2_client_tls(&pki.gateway_trust, &pki.credential).unwrap(),
    )
    .await
    .unwrap();
    let (send, recv) = client.open_bi().await.unwrap();
    (
        client,
        ControlFramed::new(send, ControlFrameLimit::default(), ControlDeadlines { read: TEST_TIMEOUT, write: TEST_TIMEOUT }),
        ControlFramed::new(recv, ControlFrameLimit::default(), ControlDeadlines { read: TEST_TIMEOUT, write: TEST_TIMEOUT }),
    )
}

#[tokio::test]
async fn v2_mtls_listener_admits_framed_hello_and_emits_session_admit() {
    let ticket_pki = pki();
    let (ticket_handler, ticket_pool) = handler();
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &ticket_pki.gateway_identity, device_trust: &ticket_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&ticket_handler),
            extractor: Arc::new(ChainExtractor { certificate: ticket_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&ticket_pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (_client, recv) = connect_and_send(address, &ticket_pki, hello(FIXTURE_TICKET, DeviceId::from_bytes([2; 16]))).await;
    let mut framed = ControlFramed::new(recv, ControlFrameLimit::default(), ControlDeadlines { read: TEST_TIMEOUT, write: TEST_TIMEOUT });
    let response = framed.read_frame().await.unwrap();
    assert!(matches!(response.message, ControlMessage::SessionAdmit { session_id, policy_epoch: 1, .. } if session_id == sg_core::v2::SessionId::from_bytes([4; 16])));
    let admitted = timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().unwrap();
    assert_eq!(admitted.admission().owner().device_id(), DeviceId::from_bytes([2; 16]));
    assert_eq!(ticket_handler.metrics().sessions.sessions, 1);
}

#[tokio::test]
async fn admitted_connection_owns_bound_path_control_and_protocol_close_cleanup() {
    let ticket_pki = pki();
    let (ticket_handler, ticket_pool) = handler();
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &ticket_pki.gateway_identity, device_trust: &ticket_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&ticket_handler),
            extractor: Arc::new(ChainExtractor { certificate: ticket_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&ticket_pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (_client, mut send, mut recv) = connect_and_open(address, &ticket_pki).await;
    send.write_frame(&hello(FIXTURE_TICKET, DeviceId::from_bytes([2; 16]))).await.unwrap();
    let admit = recv.read_frame().await.unwrap();
    let session_id = match admit.message {
        ControlMessage::SessionAdmit { session_id, .. } => session_id,
        _ => panic!("listener must admit the authenticated session"),
    };
    let mut admitted = timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().unwrap();
    let attach = ControlFrame {
        transaction_id: 2,
        message: ControlMessage::PathAttach {
            session_id,
            path_nonce: [9; 16],
            path_epoch: 1,
            key_epoch: 7,
            metadata: Bytes::from_static(b"wifi"),
        },
    };
    send.write_frame(&attach).await.unwrap();
    admitted.handle_next_control(2).await.unwrap();
    let first_path = recv.read_frame().await.unwrap();
    assert!(matches!(&first_path.message, ControlMessage::PathAttached { session_id: reply_session, path_epoch: 1, .. } if *reply_session == session_id));
    send.write_frame(&attach).await.unwrap();
    admitted.handle_next_control(2).await.unwrap();
    assert_eq!(recv.read_frame().await.unwrap(), first_path);
    assert_eq!(ticket_handler.metrics().sessions.paths, 1);
    send.write_frame(&ControlFrame {
        transaction_id: 3,
        message: ControlMessage::Close {
            session_id,
            reason: "operator request".into(),
        },
    })
    .await
    .unwrap();
    admitted.handle_next_control(3).await.unwrap();
    assert_eq!(
        recv.read_frame().await.unwrap(),
        ControlFrame {
            transaction_id: 3,
            message: ControlMessage::Ack,
        }
    );
    let snapshot = ticket_handler.metrics().sessions;
    assert_eq!(snapshot.sessions, 0);
    assert_eq!(snapshot.paths, 0);
    assert_eq!(snapshot.authenticated_connections, 0);
    drop(admitted);
    let snapshot = ticket_handler.metrics().sessions;
    assert_eq!(snapshot.paths, 0);
    assert_eq!(snapshot.authenticated_connections, 0);
}

#[tokio::test]
async fn peer_control_stream_close_releases_connection_and_path_without_server_drop() {
    let ticket_pki = pki();
    let (ticket_handler, ticket_pool) = handler();
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &ticket_pki.gateway_identity, device_trust: &ticket_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&ticket_handler),
            extractor: Arc::new(ChainExtractor { certificate: ticket_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&ticket_pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (_client, mut send, mut recv) = connect_and_open(address, &ticket_pki).await;
    send.write_frame(&hello(FIXTURE_TICKET, DeviceId::from_bytes([2; 16]))).await.unwrap();
    let session_id = match recv.read_frame().await.unwrap().message {
        ControlMessage::SessionAdmit { session_id, .. } => session_id,
        _ => panic!("listener must admit the authenticated session"),
    };
    let mut admitted = timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().unwrap();
    send.write_frame(&ControlFrame {
        transaction_id: 2,
        message: ControlMessage::PathAttach {
            session_id,
            path_nonce: [9; 16],
            path_epoch: 1,
            key_epoch: 7,
            metadata: Bytes::from_static(b"wifi"),
        },
    })
    .await
    .unwrap();
    admitted.handle_next_control(2).await.unwrap();
    assert!(matches!(recv.read_frame().await.unwrap().message, ControlMessage::PathAttached { .. }));
    assert_eq!(ticket_handler.metrics().sessions.authenticated_connections, 1);
    assert_eq!(ticket_handler.metrics().sessions.paths, 1);

    send.into_inner().finish().unwrap();
    assert_eq!(
        admitted.handle_next_control(3).await,
        Err(streamguard_gateway::v2::listener::V2AdmissionListenerError::ControlStream)
    );

    // `admitted` remains live: cleanup must come from the failed control read.
    let snapshot = ticket_handler.metrics().sessions;
    assert_eq!(snapshot.sessions, 1);
    assert_eq!(snapshot.authenticated_connections, 0);
    assert_eq!(snapshot.paths, 0);
}

#[tokio::test]
async fn listener_sweeps_idle_sessions_before_admission() {
    let ticket_pki = pki();
    let sweep_pool = test_pool();
    let sessions = Arc::new(V2SessionManager::with_cleanup(V2SessionManagerConfig {
        maximum_sessions: 1,
        idle_ttl_ms: 10,
        maximum_paths_per_session: 1,
        maximum_pending_attaches: 1,
        pending_attach_ttl_ms: 5,
        maximum_path_epoch_history: 4,
        maximum_path_tombstones: 1,
        path_tombstone_ttl_ms: 5,
    }, vec![Arc::clone(&sweep_pool) as Arc<dyn SessionCleanup>]).unwrap());
    let stale = sessions.reserve_admission(
        SessionId::from_bytes([9; 16]),
        DeviceId::from_bytes([8; 16]),
        sg_auth::ticket::OrganizationId::from_bytes([3; 16]),
        1_000_000,
        1,
    ).unwrap();
    sessions.commit_admission(stale, 1).unwrap();
    let ticket_handler = handler_with_sessions(Arc::clone(&sessions));
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &ticket_pki.gateway_identity, device_trust: &ticket_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&ticket_handler),
            extractor: Arc::new(ChainExtractor { certificate: ticket_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&sweep_pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 11 }).await
    });
    let (_client, recv) = connect_and_send(address, &ticket_pki, hello(FIXTURE_TICKET, DeviceId::from_bytes([2; 16]))).await;
    let mut framed = ControlFramed::new(recv, ControlFrameLimit::default(), ControlDeadlines { read: TEST_TIMEOUT, write: TEST_TIMEOUT });
    assert!(matches!(framed.read_frame().await.unwrap().message, ControlMessage::SessionAdmit { .. }));
    assert!(timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().is_ok());
    let snapshot = ticket_handler.metrics().sessions;
    assert_eq!(snapshot.sessions, 1);
    assert_eq!(snapshot.sessions_idle, 1);
}

#[tokio::test]
async fn cached_path_attach_revalidates_after_control_sweep() {
    let ticket_pki = pki();
    let (ticket_handler, ticket_pool) = handler();
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &ticket_pki.gateway_identity, device_trust: &ticket_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&ticket_handler),
            extractor: Arc::new(ChainExtractor { certificate: ticket_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&ticket_pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (_client, mut send, mut recv) = connect_and_open(address, &ticket_pki).await;
    send.write_frame(&hello(FIXTURE_TICKET, DeviceId::from_bytes([2; 16]))).await.unwrap();
    let session_id = match recv.read_frame().await.unwrap().message {
        ControlMessage::SessionAdmit { session_id, .. } => session_id,
        _ => panic!("listener must admit the authenticated session"),
    };
    let mut admitted = timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().unwrap();
    let attach = ControlFrame {
        transaction_id: 2,
        message: ControlMessage::PathAttach {
            session_id,
            path_nonce: [9; 16],
            path_epoch: 1,
            key_epoch: 7,
            metadata: Bytes::from_static(b"wifi"),
        },
    };
    send.write_frame(&attach).await.unwrap();
    admitted.handle_next_control(2).await.unwrap();
    assert!(matches!(recv.read_frame().await.unwrap().message, ControlMessage::PathAttached { .. }));

    send.write_frame(&attach).await.unwrap();
    admitted.handle_next_control(120_001).await.unwrap();
    let response = recv.read_frame().await.unwrap();
    assert!(matches!(
        response.message,
        ControlMessage::Reject { code: sg_protocol::v2::control::RejectCode::InvalidState, .. }
    ), "unexpected cached-attach response: {response:?}");
    let snapshot = ticket_handler.metrics().sessions;
    assert_eq!(snapshot.sessions, 0);
    assert_eq!(snapshot.paths, 0);
    assert_eq!(snapshot.authenticated_connections, 0);
}

#[tokio::test]
async fn distinct_jtis_reuse_only_the_matching_v2_session() {
    let pki = pki();
    let (handler, pool) = handler();
    let listener = Arc::new(V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &pki.gateway_identity, device_trust: &pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&handler),
            extractor: Arc::new(ChainExtractor { certificate: pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&pool),
            config: listener_config(),
        },
    )
    .unwrap());
    let address = listener.local_addr().unwrap();
    for ticket in [FIXTURE_TICKET, FIXTURE_SECOND_TICKET] {
        let server_listener = Arc::clone(&listener);
        let server = tokio::spawn(async move {
            server_listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
        });
        let (_client, recv) = connect_and_send(address, &pki, hello(ticket, DeviceId::from_bytes([2; 16]))).await;
        let mut framed = ControlFramed::new(recv, ControlFrameLimit::default(), ControlDeadlines { read: TEST_TIMEOUT, write: TEST_TIMEOUT });
        assert!(matches!(framed.read_frame().await.unwrap().message, ControlMessage::SessionAdmit { .. }));
        assert!(timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().is_ok());
    }
    assert_eq!(handler.metrics().sessions.sessions, 1);
    assert_eq!(handler.metrics().admitted, 2);
    let conflicting_listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &pki.gateway_identity, device_trust: &pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&handler),
            extractor: Arc::new(ChainExtractor { certificate: pki.client_certificate.clone(), device_id: DeviceId::from_bytes([8; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let conflicting_address = conflicting_listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        conflicting_listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (client, _recv) = connect_and_send(
        conflicting_address,
        &pki,
        hello(FIXTURE_CONFLICT_TICKET, DeviceId::from_bytes([8; 16])),
    )
    .await;
    assert!(timeout(TEST_TIMEOUT, client.closed()).await.is_ok());
    assert!(timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().is_err());
    assert_eq!(handler.metrics().sessions.sessions, 1);
}

#[tokio::test]
async fn identity_and_ticket_rejections_never_allocate_a_session() {
    let identity_pki = pki();
    let (identity_handler, identity_pool) = handler();
    let listener = Arc::new(V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &identity_pki.gateway_identity, device_trust: &identity_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&identity_handler),
            extractor: Arc::new(ChainExtractor { certificate: identity_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: true }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&identity_pool),
            config: listener_config(),
        },
    )
    .unwrap());
    let address = listener.local_addr().unwrap();
    let server_listener = Arc::clone(&listener);
    let server = tokio::spawn(async move {
        server_listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (client, _recv) = connect_and_send(address, &identity_pki, hello(FIXTURE_TICKET, DeviceId::from_bytes([2; 16]))).await;
    assert!(timeout(TEST_TIMEOUT, client.closed()).await.is_ok());
    assert!(timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().is_err());
    assert_eq!(identity_handler.metrics().sessions.sessions, 0);

    let ticket_pki = pki();
    let (ticket_handler, ticket_pool) = handler();
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &ticket_pki.gateway_identity, device_trust: &ticket_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&ticket_handler),
            extractor: Arc::new(ChainExtractor { certificate: ticket_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&ticket_pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (client, _recv) = connect_and_send(address, &ticket_pki, hello("not-a-ticket", DeviceId::from_bytes([2; 16]))).await;
    assert!(timeout(TEST_TIMEOUT, client.closed()).await.is_ok());
    assert!(timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().is_err());
    assert_eq!(ticket_handler.metrics().sessions.sessions, 0);
}

#[tokio::test]
async fn mtls_rejection_never_allocates_a_session() {
    let pki = pki();
    let (handler, pool) = handler();
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &pki.gateway_identity, device_trust: &pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&handler),
            extractor: Arc::new(ChainExtractor { certificate: pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let no_identity = TestCredential {
        device_id: DeviceId::from_bytes([2; 16]),
        resolver: Arc::new(NoClientResolver),
    };
    let client = v2_connect_path(
        address,
        &GatewayName::new("localhost").unwrap(),
        v2_client_tls(&pki.gateway_trust, &no_identity).unwrap(),
    )
    .await;
    if let Ok(connection) = client {
        assert!(timeout(TEST_TIMEOUT, connection.closed()).await.is_ok());
    }
    assert!(timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().is_err());
    assert_eq!(handler.metrics().sessions.sessions, 0);
}

#[tokio::test]
async fn session_admit_carries_unique_pool_lease_and_releases_on_close() {
    use streamguard_gateway::v2::forwarding::{IpSource, UplinkForwarder};

    let ticket_pki = pki();
    let (ticket_handler, ticket_pool) = handler();
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &ticket_pki.gateway_identity, device_trust: &ticket_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&ticket_handler),
            extractor: Arc::new(ChainExtractor { certificate: ticket_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&ticket_pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (_client, mut send, mut recv) = connect_and_open(address, &ticket_pki).await;
    send.write_frame(&hello(FIXTURE_TICKET, DeviceId::from_bytes([2; 16]))).await.unwrap();
    let admit = recv.read_frame().await.unwrap();
    let (session_id, assigned_v4, assigned_v6, prefix_v4, prefix_v6) = match admit.message {
        ControlMessage::SessionAdmit {
            session_id,
            assigned_ipv4,
            assigned_ipv4_prefix_len,
            assigned_ipv6_prefix,
            assigned_ipv6_prefix_len,
            ..
        } => (session_id, assigned_ipv4, assigned_ipv6_prefix, assigned_ipv4_prefix_len, assigned_ipv6_prefix_len),
        _ => panic!("listener must admit with a pool lease"),
    };
    assert_eq!(session_id, sg_core::v2::SessionId::from_bytes([4; 16]));
    assert_eq!(prefix_v4, 24);
    assert_eq!(prefix_v6, 64);
    assert_ne!(assigned_v4, [0, 0, 0, 0]);
    assert_ne!(assigned_v4, [10, 64, 0, 1], "SessionAdmit must never hand out the gateway address");
    let lease = ticket_pool.lookup(session_id).expect("admission must reserve a pool lease");
    assert_eq!(lease.ipv4, assigned_v4);
    assert_eq!(lease.ipv6_prefix, assigned_v6);
    // WP-400 ordering: SessionAdmit is written only after the session
    // commits AND the lease commits to Active durably. A Reserved-only lease
    // must never validate.
    let active = ticket_pool
        .lookup_active(session_id)
        .expect("admission must commit the lease to Active before SessionAdmit");
    assert_eq!(active, lease);
    assert_eq!(ticket_pool.snapshot().active, 1);
    assert_eq!(ticket_pool.snapshot().pending, 0);
    // The sealed forwarder accepts the leased source before any TUN write.
    let forwarder = UplinkForwarder::new(Arc::clone(&ticket_pool), 1_500).unwrap();
    let mut v4_packet = vec![0u8; 20];
    v4_packet[0] = 0x45;
    v4_packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    v4_packet[12..16].copy_from_slice(&assigned_v4);
    v4_packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
    let validated = forwarder
        .validate(session_id, bytes::Bytes::from(v4_packet))
        .expect("leased source must validate");
    assert_eq!(validated.source(), IpSource::V4(assigned_v4));
    // A spoofed source for the same session is dropped before forwarding.
    let mut spoof = vec![0u8; 20];
    spoof[0] = 0x45;
    spoof[2..4].copy_from_slice(&20u16.to_be_bytes());
    spoof[12..16].copy_from_slice(&[10, 64, 0, 99]);
    spoof[16..20].copy_from_slice(&[8, 8, 8, 8]);
    assert!(forwarder.validate(session_id, bytes::Bytes::from(spoof)).is_err());
    let mut admitted = timeout(TEST_TIMEOUT, server).await.unwrap().unwrap().unwrap();
    // Exercise the reliable control path once so the pool sweep on control
    // ticks runs against a live lease.
    send.write_frame(&ControlFrame {
        transaction_id: 2,
        message: ControlMessage::PathAttach {
            session_id,
            path_nonce: [9; 16],
            path_epoch: 1,
            key_epoch: 7,
            metadata: bytes::Bytes::from_static(b"wifi"),
        },
    })
    .await
    .unwrap();
    admitted.handle_next_control(2).await.unwrap();
    assert!(matches!(recv.read_frame().await.unwrap().message, ControlMessage::PathAttached { .. }));
    // Protocol close releases the session and, via cleanup, the lease.
    send.write_frame(&ControlFrame {
        transaction_id: 3,
        message: ControlMessage::Close { session_id, reason: "test done".into() },
    })
    .await
    .unwrap();
    admitted.handle_next_control(3).await.unwrap();
    assert_eq!(
        recv.read_frame().await.unwrap(),
        ControlFrame { transaction_id: 3, message: ControlMessage::Ack }
    );
    assert!(ticket_pool.lookup(session_id).is_none(), "session close must release the lease");
    assert_eq!(ticket_pool.snapshot().active, 0);
    // A well-known pool implementation detail for determinism: the first
    // lease in a fresh /24 is .2, so a reviewer can eyeball the wire.
    assert_eq!(assigned_v4, [10, 64, 0, 2]);
}

#[tokio::test]
async fn reserve_store_failure_admits_no_session_and_writes_no_session_admit() {
    use streamguard_gateway::v2::address_pool::{InMemoryLeaseStore, LeaseStore};

    let ticket_pki = pki();
    let failing_store = Arc::new(InMemoryLeaseStore::new());
    failing_store.fail_next_persists(1);
    let pool = Arc::new(
        streamguard_gateway::v2::address_pool::AddressPool::with_store(
            address_pool_config(),
            Arc::clone(&failing_store) as Arc<dyn LeaseStore>,
            1,
        )
        .unwrap(),
    );
    let sessions = session_manager_with_pool(&pool);
    let failing_handler = handler_with_sessions(sessions);
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &ticket_pki.gateway_identity, device_trust: &ticket_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&failing_handler),
            extractor: Arc::new(ChainExtractor { certificate: ticket_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (_client, mut send, mut recv) = connect_and_open(address, &ticket_pki).await;
    send.write_frame(&hello(FIXTURE_TICKET, DeviceId::from_bytes([2; 16]))).await.unwrap();
    // No SessionAdmit is ever written: the durable reserve fails closed, so
    // the server unwinds the admission and closes the connection. A timed
    // read must fail (closed stream) rather than yield SessionAdmit.
    let read = timeout(TEST_TIMEOUT, recv.read_frame()).await;
    let wrote_admit = matches!(
        read,
        Ok(Ok(frame)) if matches!(frame.message, ControlMessage::SessionAdmit { .. })
    );
    assert!(!wrote_admit, "failed reserve must write no SessionAdmit");
    let server_result = timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
    assert!(matches!(
        server_result,
        Err(streamguard_gateway::v2::listener::V2AdmissionListenerError::AddressPool)
    ));
    assert_eq!(failing_handler.metrics().sessions.sessions, 0, "failed reserve must allocate no session");
    assert!(pool.lookup(SessionId::from_bytes([4; 16])).is_none());
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(pool.snapshot().pending, 0);
}

#[derive(Debug)]
struct FailActivePersistStore {
    inner: streamguard_gateway::v2::address_pool::InMemoryLeaseStore,
}

impl FailActivePersistStore {
    fn new() -> Self {
        Self { inner: streamguard_gateway::v2::address_pool::InMemoryLeaseStore::new() }
    }
}

impl streamguard_gateway::v2::address_pool::LeaseStore for FailActivePersistStore {
    fn load(&self) -> Result<Vec<streamguard_gateway::v2::address_pool::PersistedLease>, streamguard_gateway::v2::address_pool::StoreError> {
        self.inner.load()
    }

    fn persist(&self, lease: &streamguard_gateway::v2::address_pool::PersistedLease) -> Result<(), streamguard_gateway::v2::address_pool::StoreError> {
        if lease.state == streamguard_gateway::v2::address_pool::LeaseState::Active {
            return Err(streamguard_gateway::v2::address_pool::StoreError::Io);
        }
        self.inner.persist(lease)
    }

    fn release(&self, session_id: &SessionId) -> Result<(), streamguard_gateway::v2::address_pool::StoreError> {
        self.inner.release(session_id)
    }
}

#[tokio::test]
async fn commit_store_failure_unwinds_session_and_writes_no_session_admit() {
    // The Active commit fails durably after the session commits: the
    // listener must unwind the just-committed session, release the Reserved
    // lease, close the connection, and write no SessionAdmit.
    let ticket_pki = pki();
    let failing_store: Arc<FailActivePersistStore> = Arc::new(FailActivePersistStore::new());
    let pool = Arc::new(
        streamguard_gateway::v2::address_pool::AddressPool::with_store(
            address_pool_config(),
            Arc::clone(&failing_store) as Arc<dyn streamguard_gateway::v2::address_pool::LeaseStore>,
            1,
        )
        .unwrap(),
    );
    let sessions = session_manager_with_pool(&pool);
    let failing_handler = handler_with_sessions(sessions);
    let listener = V2AdmissionListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        V2AdmissionTls { gateway_identity: &ticket_pki.gateway_identity, device_trust: &ticket_pki.device_trust },
        V2AdmissionListenerSetup {
            handler: Arc::clone(&failing_handler),
            extractor: Arc::new(ChainExtractor { certificate: ticket_pki.client_certificate.clone(), device_id: DeviceId::from_bytes([2; 16]), reject: false }),
            trust: trust(),
            template: template(),
            address_pool: Arc::clone(&pool),
            config: listener_config(),
        },
    )
    .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        listener.accept_one_at(AdmissionTime { unix_seconds: 1_000, monotonic_millis: 1 }).await
    });
    let (_client, mut send, mut recv) = connect_and_open(address, &ticket_pki).await;
    send.write_frame(&hello(FIXTURE_TICKET, DeviceId::from_bytes([2; 16]))).await.unwrap();
    let read = timeout(TEST_TIMEOUT, recv.read_frame()).await;
    let wrote_admit = matches!(
        read,
        Ok(Ok(frame)) if matches!(frame.message, ControlMessage::SessionAdmit { .. })
    );
    assert!(!wrote_admit, "failed Active commit must write no SessionAdmit");
    let server_result = timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
    assert!(matches!(
        server_result,
        Err(streamguard_gateway::v2::listener::V2AdmissionListenerError::AddressPool)
    ));
    assert_eq!(failing_handler.metrics().sessions.sessions, 0, "failed commit must unwind the session");
    assert!(pool.lookup(SessionId::from_bytes([4; 16])).is_none());
    assert!(pool.lookup_active(SessionId::from_bytes([4; 16])).is_none());
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(pool.snapshot().pending, 0);
}

#[test]
fn expired_lease_sweep_closes_its_session() {
    use streamguard_gateway::v2::address_pool::{AddressPool, AddressPoolConfig, InMemoryLeaseStore, LeaseStore};
    use streamguard_gateway::v2::session_manager::{SessionCleanup, V2SessionManager, V2SessionManagerConfig};

    // Mirrors exactly what the listener does on every accept and control
    // tick: sweep the pool, then close each expired session by ID. An
    // expired Active lease must never leave a live session without
    // addresses, even when no new admission arrives.
    let store = Arc::new(InMemoryLeaseStore::new());
    let config = AddressPoolConfig::new(
        [10, 64, 0, 0],
        24,
        [10, 64, 0, 1],
        vec![],
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        48,
        4,
        5_000,
        10_000,
        4,
    )
    .unwrap();
    let pool = Arc::new(AddressPool::with_store(config, Arc::clone(&store) as Arc<dyn LeaseStore>, 1_000).unwrap());
    let sessions = Arc::new(
        V2SessionManager::with_cleanup(
            V2SessionManagerConfig {
                maximum_sessions: 4,
                idle_ttl_ms: 120_000,
                maximum_paths_per_session: 1,
                maximum_pending_attaches: 1,
                pending_attach_ttl_ms: 5_000,
                maximum_path_epoch_history: 4,
                maximum_path_tombstones: 1,
                path_tombstone_ttl_ms: 5_000,
            },
            vec![Arc::clone(&pool) as Arc<dyn SessionCleanup>],
        )
        .unwrap(),
    );
    let session_id = SessionId::from_bytes([55; 16]);
    let device_id = DeviceId::from_bytes([56; 16]);
    let reservation = sessions
        .reserve_admission(session_id, device_id, sg_auth::ticket::OrganizationId::from_bytes([3; 16]), 1_000_000, 1_000)
        .unwrap();
    pool.reserve(session_id, device_id, 1_000).unwrap();
    sessions.commit_admission(reservation, 1_000).unwrap();
    pool.commit(session_id, 1_000).unwrap();
    assert!(pool.lookup_active(session_id).is_some());
    // Past the 10 s lease TTL the pool sweep expires the lease and reports
    // the session; the listener then closes it by ID (idempotent).
    let expired = pool.sweep(1_000 + 10_000);
    assert_eq!(expired, vec![session_id]);
    for expired_session in expired {
        assert!(sessions.close(expired_session).unwrap());
    }
    assert!(pool.lookup(session_id).is_none());
    assert!(pool.lookup_active(session_id).is_none());
    assert_eq!(sessions.snapshot().sessions, 0);
}
