//! Isolated V2 QUIC control-admission listener.
//!
//! This listener creates its endpoint with `v2_server_tls` only. It admits one
//! mTLS-authenticated, framed `ClientHello`, replies with `SessionAdmit`, and
//! never opens a V1 tunnel, reads datagrams, or accesses a TUN/flow table.
//!
//! Production expiry is owned by [`super::setup::V2GatewaySetup`]: build the
//! admission handler from `setup.sessions()` and this setup from
//! `setup.pool()` plus that handler, then hold the setup alongside the
//! listener. The per-accept/per-control sweeps below stay as an opportunistic
//! fast path; the setup-owned autonomous tasks are the guarantee when no
//! traffic arrives.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sg_auth::device::{
    DeviceTrustAnchors, GatewayTlsIdentity, VerifiedPeerDeviceIdentityExtractor,
};
use sg_auth::ticket::ControllerTrustSnapshot;
use sg_core::v2::PathId;
use sg_protocol::v2::control::{
    ControlFrame, ControlFrameLimit, ControlMessage, RejectCode, SafeModePolicy,
};
use sg_transport::quic::{v2_peer_device_identity, v2_server_tls};
use sg_transport::v2::{ControlDeadlines, ControlFramed};
use thiserror::Error;

use super::address_pool::{AddressPool, AssignedAddresses};
use super::admission::{
    AdmissionAccepted, AdmissionHandler, AdmissionTime,
    BoundedClientHello,
};
use super::persistence::PoolTime;
use super::session_manager::{AuthenticatedConnection, Clock};

/// Policy template for V2 `SessionAdmit`. Addresses are never static: the
/// listener reserves a bounded [`AddressPool`] lease per session and echoes
/// that lease here. The template owns only the validated Safe Mode policy;
/// prefix lengths come from the lease so pool and wire can never disagree.
#[derive(Clone)]
pub struct SessionAdmitTemplate {
    safe_mode_policy: SafeModePolicy,
}

impl SessionAdmitTemplate {
    pub fn new(safe_mode_policy: SafeModePolicy) -> Self {
        Self { safe_mode_policy }
    }

    fn frame(
        &self,
        transaction_id: u64,
        admitted: AdmissionAccepted,
        lease: &AssignedAddresses,
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
                assigned_ipv4: lease.ipv4,
                assigned_ipv4_prefix_len: lease.ipv4_prefix_len,
                assigned_ipv6_prefix: lease.ipv6_prefix,
                assigned_ipv6_prefix_len: lease.ipv6_prefix_len,
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
/// Production builds `handler` from [`super::setup::V2GatewaySetup::sessions`]
/// and `address_pool` from [`super::setup::V2GatewaySetup::pool`] so admission
/// and the autonomous setup-owned sweeps resolve one shared map.
pub struct V2AdmissionListenerSetup<V> {
    pub handler: Arc<AdmissionHandler<V>>,
    pub extractor: Arc<dyn VerifiedPeerDeviceIdentityExtractor>,
    pub trust: Arc<ControllerTrustSnapshot>,
    pub template: SessionAdmitTemplate,
    pub address_pool: Arc<AddressPool>,
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
    address_pool: Arc<AddressPool>,
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
        let V2AdmissionListenerSetup { handler, extractor, trust, template, address_pool, config } = setup;
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
        Ok(Self { endpoint, handler, extractor, trust, template, address_pool, config })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, V2AdmissionListenerError> {
        self.endpoint.local_addr().map_err(|_| V2AdmissionListenerError::Endpoint)
    }

    /// Closes the QUIC endpoint to new and existing connections. A pending
    /// [`V2AdmissionListener::accept_one_at`] observes `EndpointClosed` and a
    /// blocked control-stream read fails promptly, so the admission-only
    /// runtime shutdown never hangs. Idempotent.
    pub fn close(&self) {
        self.endpoint.close(quinn::VarInt::from_u32(0), b"v2 gateway shutdown");
    }

    /// Accepts one V2 control admission using the lifecycle clock. The
    /// `AdmissionTime` is derived from the injected clock so ticket claims
    /// are validated against real unix time while TTL-based state uses
    /// monotonic time. A limiter permit is acquired from the peer's UDP
    /// source before beginning the QUIC handshake and released by RAII
    /// after it completes or times out. No mutex guard crosses an await.
    pub async fn accept_one(
        &self,
        clock: &dyn Clock,
    ) -> Result<V2AdmittedConnection<V>, V2AdmissionListenerError> {
        self.accept_one_at(AdmissionTime {
            unix_seconds: clock.unix_seconds(),
            monotonic_millis: clock.monotonic_ms(),
        })
        .await
    }

    /// Deterministic admission entry point. Callers supply the exact
    /// [`AdmissionTime`], which keeps resource policy and ticket validation
    /// fully reproducible without a real clock. Production callers should
    /// use [`accept_one`](Self::accept_one) with the lifecycle clock.
    pub async fn accept_one_at(
        &self,
        now: AdmissionTime,
    ) -> Result<V2AdmittedConnection<V>, V2AdmissionListenerError> {
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
        if self.handler.sweep(admission_now.monotonic_millis).is_err() {
            close_rejected(&connection);
            return Err(V2AdmissionListenerError::AdmissionRejected);
        }
        // Expire stale leases before admitting so a leaked reservation can
        // never block a live session. Expired Active leases also close their
        // sessions here (idempotent): an expired lease must never leave a
        // live session without addresses. Lock order is always session map
        // then address pool (cleanup runs after the map lock), so sweeping
        // the pool first and then closing sessions cannot deadlock. Pool and
        // replay I/O run on the supervised owner queue (hard cap,
        // backpressure, timeout fail-closed), never on this executor thread,
        // and no mutex guard is held across any await below.
        //
        // Wall-aware sweep: the durable journal uses wall time, memory uses
        // monotonic (see `PoolTime`); both derive from the same `admission_now`
        // so a restart converts correctly.
        let pool_now = PoolTime::from_monotonic_and_wall_seconds(
            admission_now.monotonic_millis,
            admission_now.unix_seconds,
        );
        for expired_session in Arc::clone(&self.address_pool).sweep_at_time_async(pool_now).await {
            let _ = self.handler.close_session_by_id(expired_session);
        }
        let admitted = match self
            .handler
            .admit_async(
                source,
                peer,
                &hello,
                Some(self.trust.as_ref()),
                now.monotonic_millis,
                admission_now,
            )
            .await
        {
            Ok(admitted) => admitted,
            Err(_) => {
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::AdmissionRejected);
            }
        };
        // WP-400 atomic ordering: durable replay consume (bounded owner queue
        // with timeout) -> durable reserve -> session commit -> lease
        // Active commit (durable) -> frame and write `SessionAdmit`. No
        // session is ever advertised without a unique durable lease, and no
        // `SessionAdmit` is written before both commits are durable. Resume
        // is idempotent: the same session plus device receives the same lease.
        // Pool and replay I/O run on the supervised owner queue (no store I/O
        // under an async-held mutex, no blocking journal writes on this
        // thread, hard cap/backpressure/fail-closed).
        let reserved = match Arc::clone(&self.address_pool)
            .reserve_at_time_async(
                admitted.owner().session_id(),
                admitted.owner().device_id(),
                pool_now,
            )
            .await
        {
            Ok(lease) => lease,
            Err(_) => {
                self.handler.abort(admitted);
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::AddressPool);
            }
        };
        let authenticated_connection = match self.handler.commit_and_bind(admitted, admission_now) {
            Ok(connection) => connection,
            Err(_) => {
                let _ = Arc::clone(&self.address_pool).release_async(admitted.owner().session_id()).await;
                self.handler.abort(admitted);
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::AdmissionRejected);
            }
        };
        // Commit the Reserved lease to Active durably AFTER the session
        // commits. A store failure here unwinds the just-committed session
        // (the explicit durable release below runs first for a prompt delete;
        // the session cleanup path quarantines non-blockingly as a fallback,
        // idempotent with the explicit release) so no address leaks and no
        // `SessionAdmit` is advertised without a durable Active lease.
        let lease = match Arc::clone(&self.address_pool).commit_at_time_async(admitted.owner().session_id(), pool_now).await {
            Ok(lease) => {
                debug_assert_eq!(lease, reserved, "commit must promote the reserved lease unchanged");
                lease
            }
            Err(_) => {
                let _ = Arc::clone(&self.address_pool).release_async(admitted.owner().session_id()).await;
                let _ = self.handler.close_session(authenticated_connection);
                close_rejected(&connection);
                return Err(V2AdmissionListenerError::AddressPool);
            }
        };
        let response = match self.template.frame(hello_frame.transaction_id, admitted, &lease) {
            Ok(response) => response,
            Err(error) => {
                let _ = Arc::clone(&self.address_pool).release_async(admitted.owner().session_id()).await;
                let _ = self.handler.close_session(authenticated_connection);
                close_rejected(&connection);
                return Err(error);
            }
        };
        let mut framed_send = ControlFramed::new(send, self.config.control_frame_limit, self.config.control_deadlines);
        if framed_send.write_frame(&response).await.is_err() {
            let _ = Arc::clone(&self.address_pool).release_async(admitted.owner().session_id()).await;
            let _ = self.handler.close_session(authenticated_connection);
            close_rejected(&connection);
            return Err(V2AdmissionListenerError::ResponseWrite);
        }
        Ok(V2AdmittedConnection {
            connection,
            admitted,
            authenticated_connection: Some(authenticated_connection),
            attached_path: None,
            handler: Arc::clone(&self.handler),
            address_pool: Arc::clone(&self.address_pool),
            control_send: framed_send,
            control_recv: framed_recv,
        })
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

/// Holds the admitted Quinn connection and its one reliable control stream.
/// It intentionally exposes no datagram, TUN, or flow API.
pub struct V2AdmittedConnection<V: sg_auth::device::AdmissionTicketValidator> {
    connection: quinn::Connection,
    admitted: AdmissionAccepted,
    authenticated_connection: Option<AuthenticatedConnection>,
    attached_path: Option<ListenerPathBinding>,
    handler: Arc<AdmissionHandler<V>>,
    address_pool: Arc<AddressPool>,
    control_send: ControlFramed<quinn::SendStream>,
    control_recv: ControlFramed<quinn::RecvStream>,
}

#[derive(Clone, Copy)]
struct ListenerPathBinding {
    path_id: PathId,
    path_epoch: u64,
    key_epoch: u32,
    path_nonce: [u8; 16],
}

impl<V: sg_auth::device::AdmissionTicketValidator> V2AdmittedConnection<V> {
    #[must_use]
    pub fn admission(&self) -> AdmissionAccepted {
        self.admitted
    }

    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Processes one reliable path-control request. Path attachment, detach,
    /// and close are bound to this listener-created authenticated connection.
    ///
    /// Test/legacy entry point: `now_ms` supplies both clock domains
    /// (`PoolTime::from_monotonic`). Production must use
    /// [`V2AdmittedConnection::handle_next_control_at_time`] with a real wall
    /// clock so durable lease renewal survives a restart.
    pub async fn handle_next_control(&mut self, now_ms: u64) -> Result<(), V2AdmissionListenerError> {
        self.handle_next_control_at_time(PoolTime::from_monotonic(now_ms)).await
    }

    /// Wall-aware control processing with authenticated activity renewal (V2
    /// Safe Mode renewal policy).
    ///
    /// Every valid control that proves liveness — a new `PathAttach` commit, a
    /// cached `PathAttach` revalidation, or a successful `PathDetach` — renews
    /// the session's Active lease to `now + lease_ttl` through the bounded
    /// owner queue with the gateway's wall time (`PoolTime`), and records
    /// session activity (`last_activity_ms`) for the idle TTL. Renewal happens
    /// before any path-state mutation (new attach/detach) or before replaying
    /// a cached success, so invalid/spoofed activity never extends a lease and
    /// renewal failures fail closed with no success frame (`AddressPool`
    /// error, no `Ack`/`PathAttached` written). Expired/idle sessions are
    /// removed with cleanup; `Close` terminates without renewal. Never logs
    /// identities or tickets.
    pub async fn handle_next_control_at_time(&mut self, now: PoolTime) -> Result<(), V2AdmissionListenerError> {
        let now_ms = now.monotonic_ms;
        let frame = match self.control_recv.read_frame().await {
            Ok(frame) => frame,
            Err(_) => {
                let _ = self.close();
                return Err(V2AdmissionListenerError::ControlStream);
            }
        };
        self.handler.sweep(now_ms).map_err(|_| V2AdmissionListenerError::ConnectionCleanup)?;
        // Retry durable address releases and expire stale leases on every
        // control tick. Expired leases close their sessions here
        // (idempotent) so an expired Active lease never leaves a live
        // session without addresses, even when no new admission arrives to
        // drive the accept-path sweep. Pool I/O runs on the bounded blocking
        // pool, never on this executor thread.
        for expired_session in Arc::clone(&self.address_pool).sweep_at_time_async(now).await {
            let _ = self.handler.close_session_by_id(expired_session);
        }
        let response = match frame.message {
            ControlMessage::PathAttach {
                session_id,
                path_nonce,
                path_epoch,
                key_epoch,
                ..
            } if session_id == self.admitted.owner().session_id() => {
                if let Some(path) = self.attached_path {
                    if path.path_epoch == path_epoch && path.key_epoch == key_epoch && path.path_nonce == path_nonce {
                        let connection = self.authenticated_connection.ok_or(V2AdmissionListenerError::ConnectionClosed)?;
                        if self
                            .handler
                            .validate_attached_path(connection, path.path_id, path.path_epoch, path.key_epoch, now_ms)
                            .is_ok()
                        {
                            // Authenticated activity renewal: a cached revalidation
                            // proves liveness, so renew the Active lease through
                            // the bounded owner queue with wall time before
                            // replaying success. Renewal failures fail closed
                            // (no `PathAttached`, session closed when expired).
                            if Arc::clone(&self.address_pool)
                                .renew_at_time_async(session_id, now)
                                .await
                                .is_err()
                            {
                                let _ = self.handler.close_session_by_id(session_id);
                                return Err(V2AdmissionListenerError::AddressPool);
                            }
                            ControlFrame {
                                transaction_id: frame.transaction_id,
                                message: ControlMessage::PathAttached {
                                    session_id,
                                    path_id: path.path_id,
                                    path_epoch,
                                },
                            }
                        } else {
                            reject(frame.transaction_id, RejectCode::InvalidState, "cached path attachment is no longer valid")
                        }
                    } else {
                        reject(frame.transaction_id, RejectCode::StaleEpoch, "connection is already attached")
                    }
                } else {
                let connection = self.authenticated_connection.ok_or(V2AdmissionListenerError::ConnectionClosed)?;
                // Authenticated activity renewal before any path-state
                // mutation: record session liveness and renew the Active lease
                // through the bounded owner queue with wall time. Invalid or
                // expired activity never allocates a path; renewal failures
                // fail closed with no success frame.
                if self.handler.record_authenticated_activity(connection, now_ms).is_err() {
                    let _ = self.handler.close_session_by_id(session_id);
                    return Err(V2AdmissionListenerError::AddressPool);
                }
                if Arc::clone(&self.address_pool).renew_at_time_async(session_id, now).await.is_err() {
                    let _ = self.handler.close_session_by_id(session_id);
                    return Err(V2AdmissionListenerError::AddressPool);
                }
                match self.handler.reserve_attach(connection, path_epoch, key_epoch, now_ms) {
                    Ok(reservation) => match self.handler.commit_attach(reservation) {
                        Ok(path) => {
                            self.attached_path = Some(ListenerPathBinding {
                                path_id: path.path_id,
                                path_epoch: path.path_epoch,
                                key_epoch: path.key_epoch,
                                path_nonce,
                            });
                            ControlFrame {
                                transaction_id: frame.transaction_id,
                                message: ControlMessage::PathAttached {
                                    session_id,
                                    path_id: path.path_id,
                                    path_epoch: path.path_epoch,
                                },
                            }
                        }
                        Err(_) => reject(frame.transaction_id, RejectCode::InvalidState, "path attach could not commit"),
                    },
                    Err(_) => reject(frame.transaction_id, RejectCode::InvalidState, "path attach rejected"),
                }
                }
            }
            ControlMessage::PathDetach {
                session_id,
                path_id,
                path_epoch,
                ..
            } if session_id == self.admitted.owner().session_id() => {
                let connection = self.authenticated_connection.ok_or(V2AdmissionListenerError::ConnectionClosed)?;
                // Authenticated activity renewal before mutation: a valid
                // detach proves liveness, so record session activity and renew
                // the Active lease through the bounded owner queue with wall
                // time. Failures fail closed with no `Ack` and no detach.
                if self.handler.record_authenticated_activity(connection, now_ms).is_err() {
                    let _ = self.handler.close_session_by_id(session_id);
                    return Err(V2AdmissionListenerError::AddressPool);
                }
                if Arc::clone(&self.address_pool).renew_at_time_async(session_id, now).await.is_err() {
                    let _ = self.handler.close_session_by_id(session_id);
                    return Err(V2AdmissionListenerError::AddressPool);
                }
                match self.handler.detach_connection(connection, path_id, path_epoch, now_ms) {
                    Ok(true) => {
                        self.attached_path = None;
                        ControlFrame { transaction_id: frame.transaction_id, message: ControlMessage::Ack }
                    }
                    Ok(false) => ControlFrame { transaction_id: frame.transaction_id, message: ControlMessage::Ack },
                    Err(_) => reject(frame.transaction_id, RejectCode::UnknownPath, "path detach rejected"),
                }
            }
            ControlMessage::Close { session_id, .. } if session_id == self.admitted.owner().session_id() => {
                self.close_session()?;
                ControlFrame { transaction_id: frame.transaction_id, message: ControlMessage::Ack }
            }
            _ => reject(frame.transaction_id, RejectCode::InvalidDirection, "control request is not valid for this connection"),
        };
        if self.control_send.write_frame(&response).await.is_err() {
            let _ = self.close();
            return Err(V2AdmissionListenerError::ControlStream);
        }
        Ok(())
    }

    /// Releases this connection's pending or committed path exactly once.
    pub fn close(&mut self) -> Result<bool, V2AdmissionListenerError> {
        let Some(connection) = self.authenticated_connection.take() else {
            return Ok(false);
        };
        self.attached_path = None;
        self.handler.close_connection(connection).map_err(|_| V2AdmissionListenerError::ConnectionCleanup)
    }

    /// Closes the admitted session, not just this QUIC path. The manager first
    /// invalidates every connection capability and path binding, then invokes
    /// cleanup after releasing its state lock.
    fn close_session(&mut self) -> Result<bool, V2AdmissionListenerError> {
        let Some(connection) = self.authenticated_connection.take() else {
            return Ok(false);
        };
        self.attached_path = None;
        self.handler.close_session(connection).map_err(|_| V2AdmissionListenerError::ConnectionCleanup)
    }
}

impl<V: sg_auth::device::AdmissionTicketValidator> Drop for V2AdmittedConnection<V> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl<V: sg_auth::device::AdmissionTicketValidator> fmt::Debug for V2AdmittedConnection<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("V2AdmittedConnection(REDACTED)")
    }
}

fn reject(transaction_id: u64, code: RejectCode, reason: &str) -> ControlFrame {
    ControlFrame {
        transaction_id,
        message: ControlMessage::Reject { code, reason: reason.into() },
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
    #[error("V2 authenticated connection is already closed")]
    ConnectionClosed,
    #[error("V2 authenticated connection cleanup failed")]
    ConnectionCleanup,
    #[error("V2 address lease was rejected")]
    AddressPool,
}
