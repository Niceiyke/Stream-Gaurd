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
use sg_core::error::{Error, Result};
use sg_core::{PathId, SessionId};
use sg_protocol::control::ControlMsg;
use sg_protocol::{Envelope, PacketType};

use crate::{PathTransport, SessionTicket, async_trait};

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
pub async fn connect_path(
    addr: SocketAddr,
    server_name: &str,
    config: quinn::ClientConfig,
    path_id: PathId,
) -> Result<QuicPathTransport> {
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("static bind address"))
        .map_err(|e| Error::io(e.to_string()))?;
    endpoint.set_default_client_config(config);
    let conn = endpoint
        .connect(addr, server_name)
        .map_err(|e| Error::transport(format!("connect error: {e}")))?
        .await
        .map_err(|e| Error::transport(format!("handshake failed: {e}")))?;
    Ok(QuicPathTransport::new(conn, path_id))
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
}

impl QuicPathTransport {
    pub fn new(conn: quinn::Connection, path_id: PathId) -> Self {
        Self { conn, path_id }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sg_core::Sequence;
    use sg_protocol::{PacketType, VERSION};
    use tokio::task::JoinHandle;

    fn test_cert() -> (Vec<u8>, Vec<u8>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("rcgen self-signed cert");
        (certified.cert.der().to_vec(), certified.key_pair.serialize_der())
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
}