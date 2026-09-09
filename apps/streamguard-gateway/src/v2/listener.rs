//! Isolated V2 QUIC control-admission listener.
//!
//! This listener creates its endpoint with `v2_server_tls` only. It admits one
//! mTLS-authenticated, framed `ClientHello`, replies with `SessionAdmit`, and
//! never opens a V1 tunnel, reads datagrams, or accesses a TUN/flow table.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sg_auth::device::{
    DeviceTrustAnchors, GatewayTlsIdentity, VerifiedPeerDeviceIdentityExtractor,
};
use sg_auth::ticket::ControllerTrustSnapshot;
use sg_protocol::v2::control::{
    ControlFrame, ControlFrameLimit, ControlMessage, SafeModePolicy,
};
use sg_transport::quic::{v2_peer_device_identity, v2_server_tls};
use sg_transport::v2::{ControlDeadlines, ControlFramed};
use thiserror::Error;

use super::admission::{
    AdmissionAccepted, AdmissionHandler, AdmissionTime,
    BoundedClientHello,
};

/// Static V2 control-admission data. Address allocation and policy ownership
/// move to WP-202/WP-400; these validated values only permit a bounded
/// `SessionAdmit` response after successful admission.
#[derive(Clone)]
pub struct SessionAdmitTemplate {
    assigned_ipv4: [u8; 4],
    assigned_ipv4_prefix_len: u8,
    assigned_ipv6_prefix: [u8; 16],
    assigned_ipv6_prefix_len: u8,
    safe_mode_policy: SafeModePolicy,
}

impl SessionAdmitTemplate {
    pub fn new(
        assigned_ipv4: [u8; 4],
        assigned_ipv4_prefix_len: u8,
        assigned_ipv6_prefix: [u8; 16],
        assigned_ipv6_prefix_len: u8,
        safe_mode_policy: SafeModePolicy,
    ) -> Result<Self, V2AdmissionListenerError> {
        if assigned_ipv4.iter().all(|byte| *byte == 0)
            || assigned_ipv4_prefix_len == 0
            || assigned_ipv4_prefix_len > 32
            || assigned_ipv6_prefix.iter().all(|byte| *byte == 0)
            || assigned_ipv6_prefix_len == 0
            || assigned_ipv6_prefix_len > 128
        {
            return Err(V2AdmissionListenerError::InvalidConfiguration);
        }
        Ok(Self {
            assigned_ipv4,
            assigned_ipv4_prefix_len,
            assigned_ipv6_prefix,
            assigned_ipv6_prefix_len,
            safe_mode_policy,
        })
    }

    fn frame(
        &self,
        transaction_id: u64,
        admitted: AdmissionAccepted,
    ) -> Result<ControlFrame, V2AdmissionListenerError> {
        let expires_at_ms = admitted
            .expires_at_unix_seconds()
            .checked_mul(1_000)
            .ok_or(V2AdmissionListenerError::InvalidAdmission)?;
        Ok(ControlFrame {
            transaction_id,
            message: ControlMessage::SessionAdmit {
                session_id: admitted.owner().session_id(),
                expires_at_ms,
                policy_epoch: admitted.policy_version(),
                assigned_ipv4: self.assigned_ipv4,
                assigned_ipv4_prefix_len: self.assigned_ipv4_prefix_len,
                assigned_ipv6_prefix: self.assigned_ipv6_prefix,
                assigned_ipv6_prefix_len: self.assigned_ipv6_prefix_len,
                safe_mode_policy: self.safe_mode_policy.clone(),
            },
        })
    }
}

impl fmt::Debug for SessionAdmitTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionAdmitTemplate(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2AdmissionListenerConfig {
    pub handshake_timeout: Duration,
    pub control_stream_timeout: Duration,
    pub control_deadlines: ControlDeadlines,
    pub control_frame_limit: ControlFrameLimit,
}

/// V2 mTLS inputs accepted by listener construction. Keeping this separate
/// makes it impossible to substitute a V1 Quinn configuration at the API.
pub struct V2AdmissionTls<'a> {
    pub gateway_identity: &'a dyn GatewayTlsIdentity,
    pub device_trust: &'a DeviceTrustAnchors,
}

/// Admission dependencies that are independent of TLS endpoint creation.
pub struct V2AdmissionListenerSetup<V> {
    pub handler: Arc<AdmissionHandler<V>>,
    pub extractor: Arc<dyn VerifiedPeerDeviceIdentityExtractor>,
    pub trust: Arc<ControllerTrustSnapshot>,
    pub template: SessionAdmitTemplate,
    pub config: V2AdmissionListenerConfig,
}

impl Default for V2AdmissionListenerConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            control_stream_timeout: Duration::from_secs(5),
            control_deadlines: ControlDeadlines::default(),
            control_frame_limit: ControlFrameLimit::default(),
        }
    }
}

/// Public V2-only listener. It does not accept a `GatewayQuic` or an arbitrary
/// Quinn server config, preventing accidental V1 TLS/accept reuse.
pub struct V2AdmissionListener<V> {
    endpoint: quinn::Endpoint,
    handler: Arc<AdmissionHandler<V>>,
    extractor: Arc<dyn VerifiedPeerDeviceIdentityExtractor>,
    trust: Arc<ControllerTrustSnapshot>,
    template: SessionAdmitTemplate,
    config: V2AdmissionListenerConfig,
}

impl<V> V2AdmissionListener<V>
where
    V: sg_auth::device::AdmissionTicketValidator + 'static,
{
    pub fn bind(
        address: SocketAddr,
        tls: V2AdmissionTls<'_>,
        setup: V2AdmissionListenerSetup<V>,
    ) -> Result<Self, V2AdmissionListenerError> {
        let V2AdmissionListenerSetup { handler, extractor, trust, template, config } = setup;
        if config.handshake_timeout.is_zero()
            || config.control_stream_timeout.is_zero()
            || config.control_deadlines.read.is_zero()
            || config.control_deadlines.write.is_zero()
            || config.control_frame_limit.maximum() == 0
        {
            return Err(V2AdmissionListenerError::InvalidConfiguration);
        }
        // The endpoint is intentionally constructed only from the V2 mTLS
        // builder, never from V1 `server_tls` or `GatewayQuic`.
        let server = v2_server_tls(tls.gateway_identity, tls.device_trust)
            .map_err(|_| V2AdmissionListenerError::TlsConfiguration)?;
        let endpoint = quinn::Endpoint::server(server, address)
            .map_err(|_| V2AdmissionListenerError::Endpoint)?;
        Ok(Self { endpoint, handler, extractor, trust, template, config })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, V2AdmissionListenerError> {
        self.endpoint.local_addr().map_err(|_| V2AdmissionListenerError::Endpoint)
    }

    /// Accepts one V2 control admission. A limiter permit is acquired from the
    /// peer's UDP source before beginning the QUIC handshake and released by
    /// RAII after it completes or times out. No mutex guard crosses an await.
    pub async fn accept_one(
        &self,
        now: AdmissionTime,
    ) -> Result<V2AdmittedConnection, V2AdmissionListenerError> {
        let accepted_at = Instant::now();
        let incoming = self.endpoint.accept().await.ok_or(V2AdmissionListenerError::EndpointClosed)?;
        let source = incoming.remote_address().ip();
        let handshake_permit = match self.handler.acquire_handshake(source, now) {
            Ok(permit) => permit,
            Err(_) => {
                incoming.refuse();
                return Err(V2AdmissionListenerError::Limited);
            }
        };
        let connection = match tokio::time::timeout(self.config.handshake_timeout, incoming).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(_)) => return Err(V2AdmissionListenerError::Handshake),
            Err(_) => return Err(V2AdmissionListenerError::HandshakeDeadline),
        };
        drop(handshake_permit);

        let peer = match v2_peer_device_identity(&connection, self.extractor.as_ref()) {
            Ok(device_id) => super::admission::verified_peer_from_transport(device_id),
            Err(_) => {
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::PeerIdentity);
            }
        };
        let (send, recv) = match tokio::time::timeout(self.config.control_stream_timeout, connection.accept_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(_)) => {
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::ControlStream);
            }
            Err(_) => {
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::ControlStreamDeadline);
            }
        };
        let mut framed_recv = ControlFramed::new(recv, self.config.control_frame_limit, self.config.control_deadlines);
        let hello_frame = match framed_recv.read_frame().await {
            Ok(frame) => frame,
            Err(_) => {
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::InvalidControl);
            }
        };
        let hello = match BoundedClientHello::from_control_message(&hello_frame.message) {
            Ok(hello) => hello,
            Err(_) => {
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::InvalidControl);
            }
        };
        // Never validate a ticket against the time the UDP accept began: a
        // handshake or control read can cross its expiry or verification budget.
        let admission_now = advance_admission_time(now, accepted_at.elapsed());
        let admitted = match self.handler.admit(
            source,
            peer,
            &hello,
            Some(self.trust.as_ref()),
            now.monotonic_millis,
            admission_now,
        ) {
            Ok(admitted) => admitted,
            Err(_) => {
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::AdmissionRejected);
            }
        };
        let response = match self.template.frame(hello_frame.transaction_id, admitted) {
            Ok(response) => response,
            Err(error) => {
                close_rejected(&connection);
                return Err(error);
            }
        };
        let mut framed_send = ControlFramed::new(send, self.config.control_frame_limit, self.config.control_deadlines);
        if framed_send.write_frame(&response).await.is_err() {
            close_rejected(&connection);
            return Err(V2AdmissionListenerError::ResponseWrite);
        }
        Ok(V2AdmittedConnection { connection, admitted })
    }
}

fn advance_admission_time(base: AdmissionTime, elapsed: Duration) -> AdmissionTime {
    AdmissionTime {
        unix_seconds: base.unix_seconds.saturating_add(elapsed.as_secs()),
        monotonic_millis: base
            .monotonic_millis
            .saturating_add(elapsed.as_millis().min(u64::MAX as u128) as u64),
    }
}

impl<V> fmt::Debug for V2AdmissionListener<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("V2AdmissionListener(REDACTED)")
    }
}

/// Holds the admitted Quinn connection. It intentionally exposes no packet or
/// path API; WP-202/WP-600 own the next lifecycle/control-stream steps.
pub struct V2AdmittedConnection {
    connection: quinn::Connection,
    admitted: AdmissionAccepted,
}

impl V2AdmittedConnection {
    #[must_use]
    pub fn admission(&self) -> AdmissionAccepted {
        self.admitted
    }

    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }
}

impl fmt::Debug for V2AdmittedConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("V2AdmittedConnection(REDACTED)")
    }
}

fn close_rejected(connection: &quinn::Connection) {
    connection.close(quinn::VarInt::from_u32(0), b"v2 admission rejected");
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum V2AdmissionListenerError {
    #[error("V2 admission listener configuration is invalid")]
    InvalidConfiguration,
    #[error("V2 admission TLS configuration failed")]
    TlsConfiguration,
    #[error("V2 admission endpoint is unavailable")]
    Endpoint,
    #[error("V2 admission endpoint is closed")]
    EndpointClosed,
    #[error("V2 admission handshake is rate limited")]
    Limited,
    #[error("V2 admission handshake failed")]
    Handshake,
    #[error("V2 admission handshake deadline elapsed")]
    HandshakeDeadline,
    #[error("V2 peer identity extraction failed")]
    PeerIdentity,
    #[error("V2 control stream failed")]
    ControlStream,
    #[error("V2 control stream deadline elapsed")]
    ControlStreamDeadline,
    #[error("V2 control request is invalid")]
    InvalidControl,
    #[error("V2 admission was rejected")]
    AdmissionRejected,
    #[error("V2 SessionAdmit is invalid")]
    InvalidAdmission,
    #[error("V2 SessionAdmit write failed")]
    ResponseWrite,
}
