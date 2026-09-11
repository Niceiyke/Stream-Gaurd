//! Real QUIC single-path transport (spec 9.5, engineering step 4).
//!
//! One independent quinn connection per physical path; the `sg_protocol`
//! envelope travels as a single QUIC datagram so the gateway scheduler can
//! sequence/deduplicate/reorder what arrives over multiple paths.
//!
//! TLS uses rustls with the ring provider (no cmake/nasm needed on
//! Windows). Demonstrated by the in-process loopback echo test below.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use sg_auth::device::{
    DeviceCredential, DeviceCredentialError, DeviceTrustAnchors, GatewayName, GatewayTlsIdentity,
    GatewayTrustAnchors, VerifiedPeerDeviceIdentityExtractor, validate_verified_peer_chain,
};
use sg_core::error::{Error, Result};
use sg_core::{PathId, SessionId};
use sg_protocol::control::ControlMsg;
use sg_protocol::{Envelope, PacketType};

use crate::{PathTransport, SessionTicket, async_trait};
use crate::mtu::{CheckedSendPermit, DatagramMtu, DatagramSendError, DatagramSender};

/// Builds the gateway's TLS/QUIC server configuration.
pub fn server_tls(cert_der: &[u8], key_der: &[u8]) -> Result<quinn::ServerConfig> {
    let certs = vec![rustls::pki_types::CertificateDer::from(cert_der.to_vec())];
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec()).into();
    let rustls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::transport(format!("tls protocol versions: {e}")))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| Error::transport(format!("tls server cert: {e}")))?;
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|e| Error::transport(format!("quic server config: {e}")))?;

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(20)));
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    config.transport = Arc::new(transport);
    Ok(config)
}

/// Builds the client's TLS/QUIC configuration trusting `trusted_cert_der`
/// as the gateway root anchor.
pub fn client_tls(trusted_cert_der: &[u8]) -> Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            trusted_cert_der.to_vec(),
        ))
        .map_err(|e| Error::transport(format!("tls trust anchor: {e}")))?;
    let rustls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::transport(format!("tls protocol versions: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|e| Error::transport(format!("quic client config: {e}")))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

/// Builds the V2 gateway TLS configuration with required, fail-closed device
/// mTLS. This is intentionally separate from the V1 `server_tls` helper.
pub fn v2_server_tls(
    identity: &dyn GatewayTlsIdentity,
    device_trust: &DeviceTrustAnchors,
) -> Result<quinn::ServerConfig> {
    let roots = root_store(device_trust.roots())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .with_crls(device_trust.crls().to_vec())
    // Do not accept stale or unknown certificate revocation status.
    .enforce_revocation_expiration()
    .build()
    .map_err(|_| Error::transport("V2 device certificate verifier configuration failed"))?;
    let rustls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::transport("V2 TLS protocol configuration failed"))?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(identity.server_cert_resolver());
    quic_server_config(rustls_config)
}

/// Builds the V2 client TLS configuration with gateway certificate and CRL
/// verification plus a resolver-backed device credential. It never constructs
/// a client configuration without an identity resolver or enables early data.
pub fn v2_client_tls(
    gateway_trust: &GatewayTrustAnchors,
    credential: &dyn DeviceCredential,
) -> Result<quinn::ClientConfig> {
    let roots = root_store(gateway_trust.roots())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .with_crls(gateway_trust.crls().to_vec())
    // Do not accept stale or unknown certificate revocation status.
    .enforce_revocation_expiration()
    .build()
    .map_err(|_| Error::transport("V2 gateway certificate verifier configuration failed"))?;
    let mut rustls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::transport("V2 TLS protocol configuration failed"))?
        .dangerous()
        // This is rustls' only construction API for an explicitly configured
        // WebPKI verifier; it is not a certificate-verification bypass.
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(credential.client_cert_resolver());
    rustls_config.enable_early_data = false;
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|_| Error::transport("V2 QUIC client configuration failed"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

/// Extracts a device identity from Quinn's rustls peer chain after a completed
/// V2 handshake. The chain cannot be supplied by an unauthenticated caller.
pub fn v2_peer_device_identity(
    connection: &quinn::Connection,
    extractor: &dyn VerifiedPeerDeviceIdentityExtractor,
) -> std::result::Result<sg_core::v2::DeviceId, DeviceCredentialError> {
    let chain = connection
        .peer_identity()
        .ok_or(DeviceCredentialError::PeerIdentityUnavailable)?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| DeviceCredentialError::PeerIdentityUnavailable)?;
    validate_verified_peer_chain(&chain)?;
    extractor.extract(&chain)
}

/// Connects one V2 QUIC path after validating a bounded DNS gateway name.
/// Unlike the V1 path helper, callers cannot pass arbitrary SNI text here.
pub async fn v2_connect_path(
    addr: SocketAddr,
    gateway_name: &GatewayName,
    config: quinn::ClientConfig,
) -> Result<quinn::Connection> {
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("static bind address"))
        .map_err(|_| Error::io("V2 QUIC endpoint creation failed"))?;
    endpoint.set_default_client_config(config);
    endpoint
        .connect(addr, gateway_name.as_str())
        .map_err(|_| Error::transport("V2 QUIC connection setup failed"))?
        .await
        .map_err(|_| Error::transport("V2 QUIC handshake failed"))
}

fn root_store(certs: &[rustls::pki_types::CertificateDer<'static>]) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert.clone())
            .map_err(|_| Error::transport("V2 trust anchor configuration failed"))?;
    }
    Ok(roots)
}

fn quic_server_config(rustls_config: rustls::ServerConfig) -> Result<quinn::ServerConfig> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|_| Error::transport("V2 QUIC server configuration failed"))?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(20)));
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    config.transport = Arc::new(transport);
    Ok(config)
}

/// Gateway-side QUIC endpoint accepting one connection per client path.
#[derive(Clone)]
pub struct GatewayQuic {
    endpoint: quinn::Endpoint,
}

impl GatewayQuic {
    pub fn bind(addr: SocketAddr, config: quinn::ServerConfig) -> Result<Self> {
        let endpoint = quinn::Endpoint::server(config, addr).map_err(|e| Error::io(e.to_string()))?;
        Ok(Self { endpoint })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(|e| Error::io(e.to_string()))
    }

    /// Accepts the next incoming connection and binds it to `path_id`.
    pub async fn accept(&self, path_id: PathId) -> Result<QuicPathTransport> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::transport("gateway endpoint closed"))?;
        let conn = incoming
            .await
            .map_err(|e| Error::transport(format!("handshake failed: {e}")))?;
        Ok(QuicPathTransport::new(conn, path_id))
    }
}

/// Client-side QUIC connection to the gateway for one physical path.
///
/// Runs on the plain ephemeral UDP socket. Use
/// [`connect_path_on_interface`] to ride a specific physical NIC out.
pub async fn connect_path(
    addr: SocketAddr,
    server_name: &str,
    config: quinn::ClientConfig,
    path_id: PathId,
) -> Result<QuicPathTransport> {
    connect_path_on_interface(addr, server_name, config, path_id, None).await
}

/// Client-side QUIC connection to the gateway for one physical path.
///
/// When `interface_index` is `Some(idx)` the client creates its own UDP
/// socket bound to that NIC (spec 8 "bound-path creation": each physical
/// path rides out its own interface so a path loss never takes a peer path
/// with it). Binding requires admin/root on real NICs; the loopback test
/// suites keep this `None` and use the plain unbound socket.
pub async fn connect_path_on_interface(
    addr: SocketAddr,
    server_name: &str,
    config: quinn::ClientConfig,
    path_id: PathId,
    interface_index: Option<u32>,
) -> Result<QuicPathTransport> {
    let mut endpoint = match interface_index {
        // A per-interface bound socket: build it ourselves with socket2
        // (which gives us the raw handle to set the platform unicast-IF
        // option), then hand it to a quinn endpoint over the same NIC.
        Some(idx) => {
            let socket = bound_udp_socket(idx)?;
            let udp: std::net::UdpSocket = socket.into();
            let runtime = quinn::default_runtime()
                .ok_or_else(|| Error::transport("quinn runtime-tokio feature not enabled"))?;
            quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                udp,
                runtime,
            )
            .map_err(|e| Error::io(e.to_string()))?
        }
        // Unbound path: keep the existing plain one-socket-per-path endpoint.
        None => quinn::Endpoint::client("0.0.0.0:0".parse().expect("static bind address"))
            .map_err(|e| Error::io(e.to_string()))?,
    };
    endpoint.set_default_client_config(config);
    let conn = endpoint
        .connect(addr, server_name)
        .map_err(|e| Error::transport(format!("connect error: {e}")))?
        .await
        .map_err(|e| Error::transport(format!("handshake failed: {e}")))?;
    match interface_index {
        Some(index) => Ok(QuicPathTransport::new_bound(conn, path_id, index)),
        None => Ok(QuicPathTransport::new(conn, path_id)),
    }
}

/// Builds a UDP socket bound only to the NIC with the given interface index.
///
/// The IPv4 unicast source-interface option is platform-specific:
///
/// - Windows: `IP_UNICAST_IF` (IPPROTO_IP=0, opt 31) with the interface
///   index in network byte order — i.e. its bytes swapped from the native
///   order, per the WinSock docs. socket2 0.5 exposes no raw `setsockopt`,
///   so we call the WinSock one directly.
/// - Linux: `IP_BOUND_IF` (index-based, kernel >= 5.7) via
///   `socket2::Socket::bind_device_by_index_v4`.
/// - Other targets: left unbound (the caller still gets a usable socket).
fn bound_udp_socket(interface_index: u32) -> Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| Error::io(e.to_string()))?;
    socket
        .set_reuse_address(false)
        .map_err(|e| Error::io(e.to_string()))?;
    socket
        .bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())
        .map_err(|e| Error::io(e.to_string()))?;

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket as _;
        let level = windows::Win32::Networking::WinSock::IPPROTO_IP;
        const IP_UNICAST_IF: i32 = 31;
        // WinSock stores the interface index in network byte order, so the
        // DWORD/UINT32 must be byte-swapped on a little-endian host.
        let optval: u32 = interface_index.swap_bytes();
        let rc = unsafe {
            windows::Win32::Networking::WinSock::setsockopt(
                windows::Win32::Networking::WinSock::SOCKET(socket.as_raw_socket() as usize),
                level.0,
                IP_UNICAST_IF,
                Some(&optval.to_ne_bytes()),
            )
        };
        if rc != 0 {
            return Err(Error::platform(format!(
                "IP_UNICAST_IF failed for interface index {interface_index}: winsock error {rc}"
            )));
        }
    }
    #[cfg(all(target_os = "linux", not(windows)))]
    {
        let index = std::num::NonZeroU32::new(interface_index).ok_or_else(|| {
            Error::platform("interface index 0 is invalid for socket binding")
        })?;
        socket
            .bind_device_by_index_v4(Some(index))
            .map_err(|e| Error::io(e.to_string()))?;
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = interface_index;
        // No portable per-NIC unicast binding on this target: leave unbound.
    }

    Ok(socket)
}

/// Performs the v1 bootstrap handshake on a fresh path (spec 15.5 /
/// engineering step 8).
///
/// The client sends a `Control::Init` with its signed session ticket; the
/// gateway replies with `Control::Ack` (path accredited for this session)
/// or `Control::Nack` (rejected). Returns the accredited session id, or
/// `Error::Auth` when the gateway refuses the ticket.
pub async fn bootstrap_v1(
    path: &QuicPathTransport,
    session_id: SessionId,
    token: &str,
) -> Result<SessionId> {
    let init = sg_protocol::control::ControlMsg::Init {
        sid: session_prefix(session_id),
        token: token.to_string(),
    };
    path.send(envelope(
        path.path_id(),
        PacketType::Control,
        session_id,
        init.encode()?,
    ))
    .await?;

    // Datagrams are unreliable; give the gateway a bounded window to reply.
    let reply = match tokio::time::timeout(
        Duration::from_secs(5),
        path.recv(),
    )
    .await
    .map_err(|_| {
        Error::auth("bootstrap: gateway did not answer the session ticket within 5s")
    })? {
        Ok(e) if e.packet_type == PacketType::Control => e,
        Ok(_) => return Err(Error::protocol("bootstrap: expected control reply")),
        Err(e) => return Err(Error::transport(format!("bootstrap: {e}"))),
    };
    match sg_protocol::control::ControlMsg::decode(&reply.payload)
        .map_err(|e| Error::protocol(format!("bootstrap: {e}")))?
    {
        ControlMsg::Ack { sid } => Ok(sg_core::SessionId::from_bytes(prefix_bytes(sid))),
        ControlMsg::Nack { sid, reason } => Err(Error::auth(format!(
            "gateway rejected session 0x{sid:08x}: {reason}"
        ))),
        other => Err(Error::protocol(format!("bootstrap: unexpected control {other:?}"))),
    }
}

fn session_prefix(id: SessionId) -> u32 {
    let b = id.as_guid().as_bytes();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn prefix_bytes(prefix: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&prefix.to_be_bytes());
    b
}

fn envelope(
    path_id: PathId,
    packet_type: PacketType,
    session_id: SessionId,
    payload: Bytes,
) -> Envelope {
    Envelope {
        version: sg_protocol::VERSION,
        packet_type,
        flags: 0,
        path_id,
        session_id,
        sequence: sg_core::Sequence::new(0),
        timestamp_ms: 0,
        payload,
    }
}

/// A single encrypted path: envelopes in, envelopes out, over QUIC datagrams.
pub struct QuicPathTransport {
    conn: quinn::Connection,
    path_id: PathId,
    /// The physical NIC this connection is bound to. `None` for unbound
    /// transports (dev simulation, gateway accept side): their QUIC stats
    /// describe whatever loopback they happen to ride, not an interface, so
    /// they must not report a bandwidth estimate (spec 13).
    bound_to_nic: Option<u32>,
}

impl QuicPathTransport {
    pub fn new(conn: quinn::Connection, path_id: PathId) -> Self {
        Self {
            conn,
            path_id,
            bound_to_nic: None,
        }
    }

    /// A connection bound to a specific NIC (per-interface socket, spec 8).
    /// Only bound transports report a bandwidth estimate.
    pub fn new_bound(conn: quinn::Connection, path_id: PathId, nic_index: u32) -> Self {
        Self {
            conn,
            path_id,
            bound_to_nic: Some(nic_index),
        }
    }
}

/// Bandwidth-delay-product estimate of achievable throughput (spec 13).
///
/// `available_kbps ≈ cwnd_bytes * 8 / rtt_sec / 1000`: the congestion window
/// bounds the bytes in flight, and dividing by the RTT yields how fast the
/// path can absorb them. Exposed separately so the loopback test can verify
/// the math without a live connection.
fn estimate_kbps(rtt: Duration, cwnd: u64) -> Option<u64> {
    let rtt_secs = rtt.as_secs_f64();
    if rtt_secs <= 0.0 || cwnd == 0 {
        return None;
    }
    let kbps = (cwnd as f64 * 8.0 / rtt_secs / 1000.0).ceil();
    Some(kbps.min(u64::MAX as f64) as u64)
}

#[async_trait]
impl PathTransport for QuicPathTransport {
    async fn send(&self, envelope: Envelope) -> Result<()> {
        let mut wire = BytesMut::with_capacity(64 + envelope.payload.len());
        envelope.encode(&mut wire)?;
        let data = wire.freeze();
        let limit = self.conn.max_datagram_size().unwrap_or(1200);
        if data.len() > limit {
            return Err(Error::transport(format!(
                "envelope {} bytes exceeds datagram limit {limit}",
                data.len()
            )));
        }
        self.conn
            .send_datagram(data)
            .map_err(|e| Error::transport(format!("send datagram: {e}")))
    }

    async fn recv(&self) -> Result<Envelope> {
        let datagram = self
            .conn
            .read_datagram()
            .await
            .map_err(|e| Error::transport(format!("recv datagram: {e}")))?;
        let mut buf: &[u8] = &datagram;
        Envelope::decode(&mut buf)
    }

    fn path_id(&self) -> PathId {
        self.path_id
    }

    fn close(&self) {
        // Sends CONNECTION_CLOSE; the peer's `recv` then errors immediately,
        // which is the hard signal the health engine keys failover on.
        self.conn.close(quinn::VarInt::from_u32(0), b"streamguard: path closed");
    }

    fn available_kbps(&self) -> Option<u64> {
        // Unbound transports do not ride a real NIC, so their congestion
        // stats measure loopback, not the path's actual capacity (spec 13 /
        // spec 8). Only interface-bound connections estimate bandwidth.
        self.bound_to_nic?;
        let path = self.conn.stats().path;
        estimate_kbps(path.rtt, path.cwnd)
    }
}

/// Client-side session holder: transport + gateway-issued ticket.
pub struct QuicSession {
    transport: QuicPathTransport,
    ticket: SessionTicket,
}

impl QuicSession {
    /// Opens the first path to the gateway and runs the v1 bootstrap
    /// handshake. `token` is the gateway-signed session ticket (spec 15.5).
    /// Fails with `Error::Auth` if the gateway refuses the ticket.
    pub async fn connect(
        addr: SocketAddr,
        server_name: &str,
        config: quinn::ClientConfig,
        session: sg_core::SessionId,
        path_id: PathId,
        token: String,
    ) -> Result<Self> {
        let transport = connect_path(addr, server_name, config, path_id).await?;
        // Verify the gateway accredits this session on the new path.
        let accredited = bootstrap_v1(&transport, session, &token).await?;
        if accredited != session {
            return Err(Error::auth(format!(
                "gateway accredited {accredited:?} for a different session than {session:?}"
            )));
        }
        let ticket = SessionTicket {
            session_id: session,
            token,
        };
        Ok(Self { transport, ticket })
    }

    pub fn transport(&self) -> &QuicPathTransport {
        &self.transport
    }

    pub fn ticket(&self) -> &SessionTicket {
        &self.ticket
    }
}

/// Maps Quinn's concrete (or missing) whole-datagram limit to a V2
/// [`DatagramMtu`] **without any fallback**.
///
/// `None` (datagrams disabled locally, unsupported by the peer, or not yet
/// negotiated) propagates as `None`: V2 admission stays denied until the
/// transport supplies a concrete limit. V1's `QuicPathTransport` keeps its
/// historical `unwrap_or(1200)`; this V2 helper deliberately never synthesizes
/// a limit.
#[must_use]
pub fn v2_checked_datagram_mtu(limit: Option<usize>) -> Option<DatagramMtu> {
    limit.and_then(|limit| DatagramMtu::new(limit).ok())
}

/// V2-only whole-datagram sender over one authenticated quinn connection.
///
/// Deliberately distinct from the V1 [`QuicPathTransport`]: it participates in
/// the V2 [`DatagramSender`] seam, reports the transport's actual
/// whole-datagram limit (never a fabricated 1200-byte fallback), and maps
/// quinn's send failures to typed [`DatagramSendError`]s so the V2 scheduler
/// can classify a rejection without inspecting packet content.
///
/// There is no public bypass: transmitting requires a [`CheckedSendPermit`]
/// that only [`crate::mtu::CheckedDatagramSender::send_checked`] can
/// construct. Public callers can wrap this handle in the checked sender and
/// query the MTU, but cannot send a raw datagram around admission.
pub struct V2QuicDatagramSender {
    conn: quinn::Connection,
}

impl V2QuicDatagramSender {
    /// Wraps an authenticated quinn connection.
    #[must_use]
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl DatagramSender for V2QuicDatagramSender {
    async fn send_datagram(
        &self,
        datagram: Bytes,
        _permit: CheckedSendPermit,
    ) -> std::result::Result<(), DatagramSendError> {
        let datagram_len = datagram.len();
        self.conn.send_datagram(datagram).map_err(|error| match error {
            quinn::SendDatagramError::TooLarge => DatagramSendError::TooLarge {
                datagram_len,
                limit: self.conn.max_datagram_size().unwrap_or(0),
            },
            quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled => {
                // No fallback: an unusable datagram path stays unusable.
                DatagramSendError::Rejected("datagram support is disabled by transport or peer".into())
            }
            quinn::SendDatagramError::ConnectionLost(_) => {
                DatagramSendError::Rejected("datagram connection lost".into())
            }
        })
    }

    fn current_datagram_mtu(&self) -> Option<DatagramMtu> {
        v2_checked_datagram_mtu(self.conn.max_datagram_size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams,
        ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, SerialNumber,
    };
    use sg_core::Sequence;
    use sg_core::v2::DeviceId as V2DeviceId;
    use sg_protocol::{PacketType, VERSION};
    use std::sync::Arc;
    use tokio::task::JoinHandle;

    const TEST_TLS_TIMEOUT: Duration = Duration::from_secs(3);

    #[derive(Debug)]
    struct TestClientResolver(Arc<rustls::sign::CertifiedKey>);

    impl rustls::client::ResolvesClientCert for TestClientResolver {
        fn resolve(
            &self,
            _root_hint_subjects: &[&[u8]],
            _sigschemes: &[rustls::SignatureScheme],
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
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
    struct TestDeviceCredential {
        device_id: V2DeviceId,
        resolver: Arc<dyn rustls::client::ResolvesClientCert>,
    }

    impl DeviceCredential for TestDeviceCredential {
        fn device_id(&self) -> V2DeviceId {
            self.device_id
        }

        fn client_cert_resolver(&self) -> Arc<dyn rustls::client::ResolvesClientCert> {
            self.resolver.clone()
        }
    }

    #[derive(Debug)]
    struct TestServerResolver(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for TestServerResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    #[derive(Debug)]
    struct TestGatewayIdentity(Arc<dyn rustls::server::ResolvesServerCert>);

    impl GatewayTlsIdentity for TestGatewayIdentity {
        fn server_cert_resolver(&self) -> Arc<dyn rustls::server::ResolvesServerCert> {
            self.0.clone()
        }
    }

    #[derive(Debug)]
    struct ExpectedChainDevice {
        certificate: rustls::pki_types::CertificateDer<'static>,
        device_id: V2DeviceId,
    }

    impl VerifiedPeerDeviceIdentityExtractor for ExpectedChainDevice {
        fn extract(
            &self,
            chain: &[rustls::pki_types::CertificateDer<'_>],
        ) -> std::result::Result<V2DeviceId, DeviceCredentialError> {
            if chain.first().is_some_and(|certificate| certificate.as_ref() == self.certificate.as_ref()) {
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
        params.serial_number = Some(SerialNumber::from(1_u64));
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        TestCa { certificate, key }
    }

    fn signed_leaf(
        ca: &TestCa,
        dns_name: &str,
        usage: ExtendedKeyUsagePurpose,
        serial: u64,
        expired: bool,
    ) -> (rustls::pki_types::CertificateDer<'static>, Vec<u8>) {
        let mut params = CertificateParams::new(vec![dns_name.into()]).unwrap();
        params.serial_number = Some(SerialNumber::from(serial));
        params.extended_key_usages = vec![usage];
        if expired {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, &ca.certificate, &ca.key).unwrap();
        (certificate.der().clone(), key.serialize_der())
    }

    fn crl(
        ca: &TestCa,
        revoked_serial: Option<u64>,
    ) -> rustls::pki_types::CertificateRevocationListDer<'static> {
        let revoked_certs = revoked_serial
            .into_iter()
            .map(|serial_number| rcgen::RevokedCertParams {
                serial_number: SerialNumber::from(serial_number),
                revocation_time: rcgen::date_time_ymd(2025, 1, 1),
                reason_code: None,
                invalidity_date: None,
            })
            .collect();
        CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2025, 1, 1),
            next_update: rcgen::date_time_ymd(2030, 1, 1),
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&ca.certificate, &ca.key)
        .unwrap()
        .into()
    }

    fn certified_key(
        certificate: rustls::pki_types::CertificateDer<'static>,
        key: Vec<u8>,
    ) -> Arc<rustls::sign::CertifiedKey> {
        Arc::new(
            rustls::sign::CertifiedKey::from_der(
                vec![certificate],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
                &rustls::crypto::ring::default_provider(),
            )
            .unwrap(),
        )
    }

    struct V2Pki {
        gateway_identity: TestGatewayIdentity,
        gateway_trust: GatewayTrustAnchors,
        device_trust: DeviceTrustAnchors,
        credential: TestDeviceCredential,
        client_certificate: rustls::pki_types::CertificateDer<'static>,
        device_id: V2DeviceId,
    }

    fn v2_pki(client_expired: bool, client_revoked: bool) -> V2Pki {
        let gateway_ca = certificate_authority("gateway-ca.test");
        let device_ca = certificate_authority("device-ca.test");
        let (server_certificate, server_key) = signed_leaf(
            &gateway_ca,
            "localhost",
            ExtendedKeyUsagePurpose::ServerAuth,
            10,
            false,
        );
        let client_serial = 20;
        let (client_certificate, client_key) = signed_leaf(
            &device_ca,
            "device.test",
            ExtendedKeyUsagePurpose::ClientAuth,
            client_serial,
            client_expired,
        );
        let gateway_identity = TestGatewayIdentity(Arc::new(TestServerResolver(certified_key(
            server_certificate,
            server_key,
        ))));
        let gateway_trust = GatewayTrustAnchors::new(
            vec![gateway_ca.certificate.der().clone()],
            vec![crl(&gateway_ca, None)],
        )
        .unwrap();
        let device_trust = DeviceTrustAnchors::new(
            vec![device_ca.certificate.der().clone()],
            vec![crl(&device_ca, client_revoked.then_some(client_serial))],
        )
        .unwrap();
        let device_id = V2DeviceId::from_bytes([0xA5; 16]);
        let credential = TestDeviceCredential {
            device_id,
            resolver: Arc::new(TestClientResolver(certified_key(
                client_certificate.clone(),
                client_key,
            ))),
        };
        V2Pki {
            gateway_identity,
            gateway_trust,
            device_trust,
            credential,
            client_certificate,
            device_id,
        }
    }

    async fn v2_server_result(
        config: quinn::ServerConfig,
        extractor: ExpectedChainDevice,
    ) -> (SocketAddr, JoinHandle<std::result::Result<V2DeviceId, DeviceCredentialError>>) {
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(TEST_TLS_TIMEOUT, endpoint.accept())
                .await
                .map_err(|_| DeviceCredentialError::PeerIdentityUnavailable)?
                .ok_or(DeviceCredentialError::PeerIdentityUnavailable)?;
            let connection = tokio::time::timeout(TEST_TLS_TIMEOUT, incoming)
                .await
                .map_err(|_| DeviceCredentialError::PeerIdentityUnavailable)?
                .map_err(|_| DeviceCredentialError::PeerIdentityUnavailable)?;
            v2_peer_device_identity(&connection, &extractor)
        });
        (address, task)
    }

    async fn assert_v2_handshake_rejected(
        server_config: quinn::ServerConfig,
        client_config: quinn::ClientConfig,
        gateway_name: GatewayName,
        expected_certificate: rustls::pki_types::CertificateDer<'static>,
    ) {
        let extractor = ExpectedChainDevice {
            certificate: expected_certificate,
            device_id: V2DeviceId::from_bytes([1; 16]),
        };
        let (address, server) = v2_server_result(server_config, extractor).await;
        let client = tokio::time::timeout(
            TEST_TLS_TIMEOUT,
            v2_connect_path(address, &gateway_name, client_config),
        )
        .await;
        match client {
            Ok(Err(_)) => {}
            // Quinn can report a client connection before the peer's mandatory
            // client-auth failure reaches the client. It must then close in a
            // bounded time and, critically, never produce a gateway accept.
            Ok(Ok(connection)) => {
                assert!(tokio::time::timeout(TEST_TLS_TIMEOUT, connection.closed()).await.is_ok());
            }
            Err(_) => panic!("V2 handshake rejection did not complete before the test deadline"),
        }
        let server = tokio::time::timeout(TEST_TLS_TIMEOUT, server).await.unwrap().unwrap();
        assert!(server.is_err(), "gateway accepted a rejected V2 mTLS handshake");
    }

    fn test_cert() -> (Vec<u8>, Vec<u8>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("rcgen self-signed cert");
        (certified.cert.der().to_vec(), certified.key_pair.serialize_der())
    }

    #[test]
    fn bdp_throughput_estimate() {
        // cwnd 100 KiB, rtt 40 ms -> 100*1024 bytes * 8 / 0.04 s / 1000 = 20.48 Mbps
        let kbps = estimate_kbps(Duration::from_millis(40), 100 * 1024).unwrap();
        assert_eq!(kbps, 20_480);

        // No window yet (fresh connection) -> no estimate.
        assert_eq!(estimate_kbps(Duration::ZERO, 0), None);
        assert_eq!(estimate_kbps(Duration::from_millis(1), 0), None);
        // rtt of zero with a positive window is meaningless too.
        assert_eq!(estimate_kbps(Duration::ZERO, 1200), None);
    }

    #[tokio::test]
    async fn quic_envelope_round_trip_loopback() {
        let (cert_der, key_der) = test_cert();
        let server_cfg = server_tls(&cert_der, &key_der).unwrap();
        let client_cfg = client_tls(&cert_der).unwrap();

        let gateway = GatewayQuic::bind("127.0.0.1:0".parse().unwrap(), server_cfg).unwrap();
        let addr = gateway.local_addr().unwrap();

        // Gateway: accept one path, echo the payload back as a PathStatus.
        let server = gateway.clone();
        let server_task: JoinHandle<Result<Envelope>> = tokio::spawn(async move {
            let path = server.accept(PathId::new(1)).await?;
            let received = path.recv().await?;
            let reply = Envelope {
                version: VERSION,
                packet_type: PacketType::PathStatus,
                flags: 0,
                path_id: received.path_id,
                session_id: received.session_id,
                sequence: Sequence::new(received.sequence.get() + 1),
                timestamp_ms: received.timestamp_ms,
                payload: received.payload.clone(),
            };
            path.send(reply.clone()).await?;
            // Wait for the client's ack so this endpoint stays alive while
            // the client reads the reply.
            let _ack = path.recv().await?;
            Ok(reply)
        });

        let client = connect_path(addr, "localhost", client_cfg, PathId::new(1))
            .await
            .unwrap();

        let request = Envelope {
            version: VERSION,
            packet_type: PacketType::Data,
            flags: 0,
            path_id: PathId::new(1),
            session_id: sg_core::SessionId::new(),
            sequence: Sequence::new(0),
            timestamp_ms: 7,
            payload: Bytes::from_static(b"ping"),
        };
        client.send(request).await.unwrap();
        let reply = client.recv().await.unwrap();
        assert_eq!(reply.packet_type, PacketType::PathStatus);
        assert_eq!(reply.sequence, Sequence::new(1));
        assert_eq!(reply.payload, Bytes::from_static(b"ping"));

        let ack = Envelope {
            version: VERSION,
            packet_type: PacketType::PathStatus,
            flags: 0,
            path_id: PathId::new(1),
            session_id: sg_core::SessionId::new(),
            sequence: Sequence::new(2),
            timestamp_ms: 7,
            payload: Bytes::new(),
        };
        client.send(ack).await.unwrap();

        let echoed = server_task.await.expect("server task panicked").unwrap();
        assert_eq!(echoed.payload, Bytes::from_static(b"ping"));
    }

    #[tokio::test]
    async fn v2_mtls_accepts_a_valid_device_and_extracts_its_verified_identity() {
        let pki = v2_pki(false, false);
        let server = v2_server_tls(&pki.gateway_identity, &pki.device_trust).unwrap();
        let client = v2_client_tls(&pki.gateway_trust, &pki.credential).unwrap();
        let extractor = ExpectedChainDevice {
            certificate: pki.client_certificate.clone(),
            device_id: pki.device_id,
        };
        let (address, server_task) = v2_server_result(server, extractor).await;
        let connection = tokio::time::timeout(
            TEST_TLS_TIMEOUT,
            v2_connect_path(address, &GatewayName::new("localhost").unwrap(), client),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(connection.peer_identity().is_some());
        assert_eq!(server_task.await.unwrap().unwrap(), pki.device_id);
    }

    #[tokio::test]
    async fn v2_mtls_rejects_unknown_gateway_ca_and_wrong_server_name() {
        let pki = v2_pki(false, false);
        let server = v2_server_tls(&pki.gateway_identity, &pki.device_trust).unwrap();
        let unknown_gateway_ca = certificate_authority("unknown-gateway-ca.test");
        let trust = GatewayTrustAnchors::new(
            vec![unknown_gateway_ca.certificate.der().clone()],
            vec![crl(&unknown_gateway_ca, None)],
        )
        .unwrap();
        let client = v2_client_tls(&trust, &pki.credential).unwrap();
        assert_v2_handshake_rejected(
            server,
            client,
            GatewayName::new("localhost").unwrap(),
            pki.client_certificate.clone(),
        )
        .await;

        let pki = v2_pki(false, false);
        let server = v2_server_tls(&pki.gateway_identity, &pki.device_trust).unwrap();
        let client = v2_client_tls(&pki.gateway_trust, &pki.credential).unwrap();
        assert_v2_handshake_rejected(
            server,
            client,
            GatewayName::new("wrong-name.test").unwrap(),
            pki.client_certificate,
        )
        .await;
    }

    #[tokio::test]
    async fn v2_mtls_rejects_missing_expired_revoked_and_unknown_device_identities() {
        let pki = v2_pki(false, false);
        let server = v2_server_tls(&pki.gateway_identity, &pki.device_trust).unwrap();
        let missing_credential = TestDeviceCredential {
            device_id: pki.device_id,
            resolver: Arc::new(NoClientResolver),
        };
        let client = v2_client_tls(&pki.gateway_trust, &missing_credential).unwrap();
        assert_v2_handshake_rejected(
            server,
            client,
            GatewayName::new("localhost").unwrap(),
            pki.client_certificate,
        )
        .await;

        let pki = v2_pki(true, false);
        let server = v2_server_tls(&pki.gateway_identity, &pki.device_trust).unwrap();
        let client = v2_client_tls(&pki.gateway_trust, &pki.credential).unwrap();
        assert_v2_handshake_rejected(
            server,
            client,
            GatewayName::new("localhost").unwrap(),
            pki.client_certificate,
        )
        .await;

        let pki = v2_pki(false, true);
        let server = v2_server_tls(&pki.gateway_identity, &pki.device_trust).unwrap();
        let client = v2_client_tls(&pki.gateway_trust, &pki.credential).unwrap();
        assert_v2_handshake_rejected(
            server,
            client,
            GatewayName::new("localhost").unwrap(),
            pki.client_certificate,
        )
        .await;

        let server_pki = v2_pki(false, false);
        let unknown_device_pki = v2_pki(false, false);
        let server = v2_server_tls(&server_pki.gateway_identity, &server_pki.device_trust).unwrap();
        let client = v2_client_tls(&server_pki.gateway_trust, &unknown_device_pki.credential).unwrap();
        assert_v2_handshake_rejected(
            server,
            client,
            GatewayName::new("localhost").unwrap(),
            server_pki.client_certificate,
        )
        .await;
    }

    #[tokio::test]
    async fn v2_verified_peer_identity_mismatch_rejects_the_control_seam() {
        let pki = v2_pki(false, false);
        let server = v2_server_tls(&pki.gateway_identity, &pki.device_trust).unwrap();
        let extractor = ExpectedChainDevice {
            certificate: rustls::pki_types::CertificateDer::from(vec![0x01]),
            device_id: pki.device_id,
        };
        let (address, server_task) = v2_server_result(server, extractor).await;
        let client = v2_client_tls(&pki.gateway_trust, &pki.credential).unwrap();
        let _connection = v2_connect_path(address, &GatewayName::new("localhost").unwrap(), client)
            .await
            .unwrap();
        assert_eq!(
            server_task.await.unwrap(),
            Err(DeviceCredentialError::PeerIdentityMismatch)
        );
    }

    #[test]
    fn v2_checked_datagram_mtu_maps_without_fallback() {
        use crate::mtu::{MAX_DATAGRAM_MTU, SAFE_MODE_MIN_DATAGRAM_MTU};
        use sg_protocol::v2::FIXED_HEADER_LEN;
        // No negotiated limit (disabled/unsupported/not yet negotiated):
        // propagates as None — never a synthesized 1200-byte limit.
        assert_eq!(v2_checked_datagram_mtu(None), None);
        // Sub-header and zero limits are not usable datagram MTUs.
        assert_eq!(v2_checked_datagram_mtu(Some(0)), None);
        assert_eq!(v2_checked_datagram_mtu(Some(FIXED_HEADER_LEN - 1)), None);
        // Exactly the fixed header is degenerate but valid.
        assert_eq!(
            v2_checked_datagram_mtu(Some(FIXED_HEADER_LEN)),
            DatagramMtu::new(FIXED_HEADER_LEN).ok()
        );
        // A real Safe-Mode limit maps 1:1.
        assert_eq!(
            v2_checked_datagram_mtu(Some(SAFE_MODE_MIN_DATAGRAM_MTU)),
            DatagramMtu::new(SAFE_MODE_MIN_DATAGRAM_MTU).ok()
        );
        // Above the hard maximum is rejected, not truncated.
        assert_eq!(v2_checked_datagram_mtu(Some(MAX_DATAGRAM_MTU + 1)), None);
    }

    #[tokio::test]
    async fn v2_checked_datagram_sender_admits_whole_datagrams_over_loopback() {
        use crate::mtu::{
            CheckedDatagramSender, CheckedSendError, MtuAdmission, MtuRejectReason,
            PacketIdSequencer,
        };
        use sg_core::v2::{
            FlowId as V2FlowId, PacketId as V2PacketId, PathId as V2PathId,
            SessionId as V2SessionId, TrafficClass,
        };
        use sg_protocol::v2::{Direction, V2Envelope, V2Header};

        let (cert_der, key_der) = test_cert();
        let server_cfg = server_tls(&cert_der, &key_der).unwrap();
        let client_cfg = client_tls(&cert_der).unwrap();

        let server_endpoint =
            quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server_endpoint.local_addr().unwrap();
        // Server: read exactly one datagram, then assert a bounded second read
        // times out (a gate-rejected envelope must never reach the wire).
        let server_task: JoinHandle<(usize, bool)> = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let conn = tokio::time::timeout(TEST_TLS_TIMEOUT, incoming)
                .await
                .unwrap()
                .unwrap();
            let first = tokio::time::timeout(TEST_TLS_TIMEOUT, conn.read_datagram())
                .await
                .unwrap()
                .unwrap();
            let second = tokio::time::timeout(Duration::from_millis(250), conn.read_datagram()).await;
            (first.len(), second.is_err())
        });

        let mut client_endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_cfg);
        let connecting = client_endpoint.connect(addr, "localhost").unwrap();
        let client_conn =
            tokio::time::timeout(TEST_TLS_TIMEOUT, connecting).await.unwrap().unwrap();

        let inner = V2QuicDatagramSender::new(client_conn.clone());
        let dm = inner
            .current_datagram_mtu()
            .expect("loopback negotiates a concrete whole-datagram limit");
        let mut sender = CheckedDatagramSender::new(inner, MtuAdmission::default());

        // Engine-owned sequencer: the pipeline previews (never advancing) and
        // commits only after the transport enqueue succeeds. No caller
        // supplied closure can advance or forge the preview.
        let mut sequencer = PacketIdSequencer::new(41);

        let full_payload = dm.effective_payload().get();
        // Atomic pipeline: query transport MTU, admit, preview a reservation,
        // build the envelope from the reservation, encode, send, commit.
        let sent_id = sender
            .send_checked(
                full_payload,
                &mut sequencer,
                |reservation| V2Envelope {
                    header: V2Header {
                        traffic_class: TrafficClass::Realtime,
                        direction: Direction::ClientToGateway,
                        session_id: V2SessionId::from_bytes([9; 16]),
                        path_id: V2PathId::new(1),
                        path_epoch: 1,
                        key_epoch: 1,
                        flow_id: V2FlowId::new(1),
                        packet_id: reservation.id(),
                    },
                    payload: Bytes::from(vec![0xCD; full_payload]),
                },
            )
            .await
            .expect("full-size datagram admitted");
        assert_eq!(sent_id, V2PacketId::new(41), "sender returns the previewed/committed ID");
        assert_eq!(sequencer.next_value(), 42, "commit advanced the counter by exactly 1");
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 1);
        assert_eq!(sender.admission().metrics().sends_rejected, 0);
        assert_eq!(sender.admission().metrics().encode_failures, 0);
        assert_eq!(sender.admission().metrics().transport_failures, 0);

        // One payload byte over the effective limit makes the whole datagram
        // over the negotiated limit: rejected at the gate, never sent, and the
        // sequencer is untouched (rejection precedes any preview).
        let mut rejected_sequencer = PacketIdSequencer::new(42);
        let error = sender
            .send_checked(
                full_payload + 1,
                &mut rejected_sequencer,
                |reservation| V2Envelope {
                    header: V2Header {
                        traffic_class: TrafficClass::Realtime,
                        direction: Direction::ClientToGateway,
                        session_id: V2SessionId::from_bytes([9; 16]),
                        path_id: V2PathId::new(1),
                        path_epoch: 1,
                        key_epoch: 1,
                        flow_id: V2FlowId::new(1),
                        packet_id: reservation.id(),
                    },
                    payload: Bytes::from(vec![0xCD; full_payload + 1]),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CheckedSendError::Rejected(MtuRejectReason::DatagramExceedsMtu { .. })
        ));
        assert_eq!(rejected_sequencer.next_value(), 42, "counter unchanged after gate rejection");
        assert_eq!(sequencer.next_value(), 42, "prior commit is unaffected by the later rejection");
        assert_eq!(sender.admission().metrics().sends_admitted, 1);
        assert_eq!(sender.admission().metrics().sends_enqueued, 1);
        assert_eq!(sender.admission().metrics().sends_rejected, 1);
        assert_eq!(sender.admission().metrics().encode_failures, 0);
        assert_eq!(sender.admission().metrics().transport_failures, 0);

        let (first_len, second_absent) =
            tokio::time::timeout(TEST_TLS_TIMEOUT, server_task).await.unwrap().unwrap();
        assert_eq!(first_len, dm.get(), "wire datagram is exactly the negotiated MTU");
        assert!(second_absent, "over-limit envelope must never reach the transport");

        client_conn.close(quinn::VarInt::from_u32(0), b"test done");
    }
}
