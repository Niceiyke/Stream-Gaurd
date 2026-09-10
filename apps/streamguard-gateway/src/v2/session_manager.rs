//! Authoritative, bounded V2 gateway session and path ownership.
//!
//! This map is the sole gateway authority for V2 admission, path ownership,
//! ingress binding validation, and removal. Resource cleanup callbacks run only
//! after the map lock is released.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sg_auth::ticket::OrganizationId;
use sg_core::v2::{DeviceId, PathId, SessionId};
use sg_protocol::v2::{Direction, V2Envelope};
use sg_session::v2::{Admission, AttachReservation, ConnectionId, LifecycleError, PathBinding, PathState, SessionState, V2Session, V2SessionConfig};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2SessionManagerConfig {
    pub maximum_sessions: usize,
    pub idle_ttl_ms: u64,
    pub maximum_paths_per_session: usize,
    pub maximum_pending_attaches: usize,
    pub pending_attach_ttl_ms: u64,
    pub maximum_path_epoch_history: usize,
    pub maximum_path_tombstones: usize,
    pub path_tombstone_ttl_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRemovalReason {
    Expired,
    Idle,
    Closed,
}

/// Identifies work future V2 resource owners must release after session removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRemoval {
    pub session_id: SessionId,
    pub device_id: DeviceId,
    pub organization_id: OrganizationId,
    pub reason: SessionRemovalReason,
}

/// Resource owners are intentionally separate from the session-map lock.
/// WP-301 and WP-400 implement these hooks for per-flow dedup/reorder,
/// scheduling, and allocated addresses respectively.
pub trait SessionCleanup: Send + Sync {
    fn remove_flows(&self, _removal: SessionRemoval) {}
    fn remove_dedup(&self, _removal: SessionRemoval) {}
    fn remove_scheduler(&self, _removal: SessionRemoval) {}
    fn release_address(&self, _removal: SessionRemoval) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionReservation {
    session_id: SessionId,
    device_id: DeviceId,
    organization_id: OrganizationId,
    expires_at_ms: u64,
    creates_session: bool,
}

impl AdmissionReservation {
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.session_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayAttachReservation {
    session_id: SessionId,
    reservation: AttachReservation,
}

/// Capability created only by the V2 mTLS listener after admission commits.
/// Its connection identity is never accepted from a public manager caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedConnection {
    session_id: SessionId,
    connection_id: ConnectionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedIngress {
    pub session_id: SessionId,
    pub path_id: PathId,
    pub path_epoch: u64,
    pub key_epoch: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2SessionManagerSnapshot {
    pub sessions: usize,
    pub admissions_pending: usize,
    pub paths: usize,
    pub pending_attaches: usize,
    pub authenticated_connections: usize,
    pub maximum_sessions: usize,
    pub maximum_paths_per_session: usize,
    pub maximum_pending_attaches: usize,
    pub maximum_authenticated_connections: usize,
    pub idle_ttl_ms: u64,
    pub pending_attach_ttl_ms: u64,
    pub path_tombstones: usize,
    pub maximum_path_tombstones_per_session: usize,
    pub path_tombstone_ttl_ms: u64,
    pub path_tombstones_expired: u64,
    pub path_tombstones_capacity_evicted: u64,
    pub path_epoch_history_entries: usize,
    pub maximum_path_epoch_history_per_session: usize,
    pub admission_capacity_rejected: u64,
    pub connection_capacity_rejected: u64,
    pub pending_attach_capacity_rejected: u64,
    pub admissions_expired: u64,
    pub pending_attaches_expired: u64,
    pub sessions_expired: u64,
    pub sessions_idle: u64,
    pub sessions_closed: u64,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum V2SessionManagerError {
    #[error("V2 session manager configuration is invalid")]
    InvalidConfiguration,
    #[error("V2 session manager state is unavailable")]
    Unavailable,
    #[error("V2 session capacity is exhausted")]
    Capacity,
    #[error("V2 session identity is invalid")]
    InvalidIdentity,
    #[error("V2 session owner does not match the existing session")]
    OwnerMismatch,
    #[error("V2 admission reservation is unknown")]
    UnknownAdmission,
    #[error("V2 session is unknown")]
    UnknownSession,
    #[error("V2 connection is already bound")]
    ConnectionAlreadyBound,
    #[error("V2 authenticated connection capacity is exhausted")]
    ConnectionCapacity,
    #[error("V2 attach reservation is unknown")]
    UnknownAttach,
    #[error("V2 ingress connection is unknown")]
    UnknownConnection,
    #[error("V2 ingress binding does not match the authenticated connection")]
    BindingMismatch,
    #[error("V2 ingress key epoch is stale")]
    StaleKeyEpoch,
    #[error("V2 ingress direction is invalid")]
    InvalidDirection,
    #[error("V2 session is expired")]
    Expired,
    #[error("V2 session is idle")]
    Idle,
    #[error("V2 lifecycle transition failed")]
    Lifecycle,
}

struct ManagedSession {
    session: V2Session,
    organization_id: OrganizationId,
    last_activity_ms: u64,
}

struct State {
    sessions: HashMap<SessionId, ManagedSession>,
    admissions: HashMap<SessionId, AdmissionReservation>,
    connections: HashMap<ConnectionId, (SessionId, PathId, u64, u32)>,
    pending_connections: HashMap<ConnectionId, PendingAttach>,
    authenticated_connections: HashMap<ConnectionId, SessionId>,
}

struct PendingAttach {
    reservation: GatewayAttachReservation,
    expires_at_ms: u64,
}

#[derive(Default)]
struct SessionManagerMetrics {
    admission_capacity_rejected: AtomicU64,
    connection_capacity_rejected: AtomicU64,
    pending_attach_capacity_rejected: AtomicU64,
    admissions_expired: AtomicU64,
    pending_attaches_expired: AtomicU64,
    sessions_expired: AtomicU64,
    sessions_idle: AtomicU64,
    sessions_closed: AtomicU64,
}

/// Concurrent gateway owner map. All methods are synchronous and deterministic
/// when callers supply `now_ms`; no timer task or lock is held during cleanup.
pub struct V2SessionManager {
    config: V2SessionManagerConfig,
    state: Mutex<State>,
    cleanup: Vec<Arc<dyn SessionCleanup>>,
    next_connection_id: AtomicU64,
    metrics: SessionManagerMetrics,
}

impl V2SessionManager {
    pub fn new(config: V2SessionManagerConfig) -> Result<Self, V2SessionManagerError> {
        Self::with_cleanup(config, Vec::new())
    }

    pub fn with_cleanup(
        config: V2SessionManagerConfig,
        cleanup: Vec<Arc<dyn SessionCleanup>>,
    ) -> Result<Self, V2SessionManagerError> {
        if config.maximum_sessions == 0
            || config.idle_ttl_ms == 0
            || config.maximum_paths_per_session == 0
            || config.maximum_pending_attaches == 0
            || config.pending_attach_ttl_ms == 0
            || config.maximum_path_epoch_history < config.maximum_paths_per_session
            || config.maximum_path_epoch_history > usize::from(u16::MAX)
            || config.maximum_path_tombstones == 0
            || config.path_tombstone_ttl_ms == 0
        {
            return Err(V2SessionManagerError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            state: Mutex::new(State {
                sessions: HashMap::new(),
                admissions: HashMap::new(),
                connections: HashMap::new(),
                pending_connections: HashMap::new(),
                authenticated_connections: HashMap::new(),
            }),
            cleanup,
            next_connection_id: AtomicU64::new(1),
            metrics: SessionManagerMetrics::default(),
        })
    }

    pub fn reserve_admission(
        &self,
        session_id: SessionId,
        device_id: DeviceId,
        organization_id: OrganizationId,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<AdmissionReservation, V2SessionManagerError> {
        if session_id.as_bytes().iter().all(|byte| *byte == 0)
            || device_id.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(V2SessionManagerError::InvalidIdentity);
        }
        if expires_at_ms == 0 || now_ms >= expires_at_ms {
            return Err(V2SessionManagerError::Expired);
        }
        let mut cleanup = None;
        let result = {
            let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
            if state.sessions.get(&session_id).is_some_and(|session| session.session.is_expired(now_ms)) {
                cleanup = remove_session(&mut state, session_id, SessionRemovalReason::Expired);
            }
            if let Some(existing) = state.sessions.get(&session_id) {
                let admission = existing.session.admission();
                if admission.device_id != device_id || existing.organization_id != organization_id {
                    Err(V2SessionManagerError::OwnerMismatch)
                } else {
                    Ok(AdmissionReservation {
                        session_id,
                        device_id,
                        organization_id,
                        expires_at_ms: admission.expires_at_ms,
                        creates_session: false,
                    })
                }
            } else if let Some(existing) = state.admissions.get(&session_id) {
                if existing.device_id != device_id || existing.organization_id != organization_id {
                    Err(V2SessionManagerError::OwnerMismatch)
                } else {
                    Ok(*existing)
                }
            } else if state.sessions.len().saturating_add(state.admissions.len()) >= self.config.maximum_sessions {
                self.metrics.admission_capacity_rejected.fetch_add(1, Ordering::Relaxed);
                Err(V2SessionManagerError::Capacity)
            } else {
                let reservation = AdmissionReservation {
                    session_id,
                    device_id,
                    organization_id,
                    expires_at_ms,
                    creates_session: true,
                };
                state.admissions.insert(session_id, reservation);
                Ok(reservation)
            }
        };
        if let Some(removal) = cleanup {
            self.record_removal(removal.reason);
            self.run_cleanup(removal);
        }
        result
    }

    pub fn commit_admission(&self, reservation: AdmissionReservation, now_ms: u64) -> Result<(), V2SessionManagerError> {
        if !reservation.creates_session {
            return Ok(());
        }
        let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
        if state.admissions.remove(&reservation.session_id) != Some(reservation) {
            return Err(V2SessionManagerError::UnknownAdmission);
        }
        let mut session = V2Session::new(
            V2SessionConfig {
                maximum_paths: self.config.maximum_paths_per_session,
                maximum_path_epoch_history: self.config.maximum_path_epoch_history,
                maximum_path_tombstones: self.config.maximum_path_tombstones,
                path_tombstone_ttl_ms: self.config.path_tombstone_ttl_ms,
            },
            Admission {
                session_id: reservation.session_id,
                device_id: reservation.device_id,
                expires_at_ms: reservation.expires_at_ms,
            },
            now_ms,
        )
        .map_err(map_lifecycle)?;
        session.activate(now_ms).map_err(map_lifecycle)?;
        state.sessions.insert(
            reservation.session_id,
            ManagedSession {
                session,
                organization_id: reservation.organization_id,
                last_activity_ms: now_ms,
            },
        );
        Ok(())
    }

    /// Commits a newly admitted session and assigns its listener-owned
    /// capability while holding the map lock. If capability allocation cannot
    /// complete, the newly committed session is removed before another caller
    /// can observe it; resource cleanup then runs after releasing the lock.
    pub(crate) fn commit_admission_and_bind(
        &self,
        reservation: AdmissionReservation,
        now_ms: u64,
    ) -> Result<AuthenticatedConnection, V2SessionManagerError> {
        if !reservation.creates_session {
            return self.bind_authenticated_connection(reservation.session_id, now_ms);
        }
        let mut cleanup = None;
        let result = {
            let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
            if state.admissions.remove(&reservation.session_id) != Some(reservation) {
                return Err(V2SessionManagerError::UnknownAdmission);
            }
            let mut session = V2Session::new(
                V2SessionConfig {
                    maximum_paths: self.config.maximum_paths_per_session,
                    maximum_path_epoch_history: self.config.maximum_path_epoch_history,
                    maximum_path_tombstones: self.config.maximum_path_tombstones,
                    path_tombstone_ttl_ms: self.config.path_tombstone_ttl_ms,
                },
                Admission {
                    session_id: reservation.session_id,
                    device_id: reservation.device_id,
                    expires_at_ms: reservation.expires_at_ms,
                },
                now_ms,
            )
            .map_err(map_lifecycle)?;
            session.activate(now_ms).map_err(map_lifecycle)?;
            state.sessions.insert(
                reservation.session_id,
                ManagedSession {
                    session,
                    organization_id: reservation.organization_id,
                    last_activity_ms: now_ms,
                },
            );
            if state.authenticated_connections.len() >= self.maximum_authenticated_connections() {
                self.metrics.connection_capacity_rejected.fetch_add(1, Ordering::Relaxed);
                cleanup = remove_session(&mut state, reservation.session_id, SessionRemovalReason::Closed);
                Err(V2SessionManagerError::ConnectionCapacity)
            } else {
                let connection_id = ConnectionId::new(self.next_connection_identity());
                state.authenticated_connections.insert(connection_id, reservation.session_id);
                Ok(AuthenticatedConnection { session_id: reservation.session_id, connection_id })
            }
        };
        if let Some(removal) = cleanup {
            self.record_removal(removal.reason);
            self.run_cleanup(removal);
        }
        result
    }

    pub fn abort_admission(&self, reservation: AdmissionReservation) -> Result<bool, V2SessionManagerError> {
        if !reservation.creates_session {
            return Ok(false);
        }
        let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
        Ok(state.admissions.remove(&reservation.session_id) == Some(reservation))
    }

    /// Creates an unforgeable-in-process capability for one connection that has
    /// completed V2 mTLS admission. This is deliberately crate-private so no
    /// external caller can present a caller-minted `ConnectionId` as trusted.
    pub(crate) fn bind_authenticated_connection(
        &self,
        session_id: SessionId,
        now_ms: u64,
    ) -> Result<AuthenticatedConnection, V2SessionManagerError> {
        let mut cleanup = None;
        let result = {
            let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
            let Some(session) = state.sessions.get(&session_id) else {
                return Err(V2SessionManagerError::UnknownSession);
            };
            if session.session.is_expired(now_ms) {
                cleanup = remove_session(&mut state, session_id, SessionRemovalReason::Expired);
                Err(V2SessionManagerError::Expired)
            } else if session.session.state() != SessionState::Active {
                Err(V2SessionManagerError::Lifecycle)
            } else if state.authenticated_connections.len() >= self.maximum_authenticated_connections() {
                self.metrics.connection_capacity_rejected.fetch_add(1, Ordering::Relaxed);
                Err(V2SessionManagerError::ConnectionCapacity)
            } else {
                let connection_id = ConnectionId::new(self.next_connection_identity());
                state.authenticated_connections.insert(connection_id, session_id);
                Ok(AuthenticatedConnection { session_id, connection_id })
            }
        };
        if let Some(removal) = cleanup {
            self.record_removal(removal.reason);
            self.run_cleanup(removal);
        }
        result
    }

    pub(crate) fn reserve_attach(
        &self,
        connection: AuthenticatedConnection,
        path_epoch: u64,
        key_epoch: u32,
        now_ms: u64,
    ) -> Result<GatewayAttachReservation, V2SessionManagerError> {
        let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
        self.prune_pending_attaches(&mut state, now_ms);
        if state.authenticated_connections.get(&connection.connection_id) != Some(&connection.session_id) {
            return Err(V2SessionManagerError::UnknownConnection);
        }
        if state.connections.contains_key(&connection.connection_id) || state.pending_connections.contains_key(&connection.connection_id) {
            return Err(V2SessionManagerError::ConnectionAlreadyBound);
        }
        if state.pending_connections.len() >= self.config.maximum_pending_attaches {
            self.metrics.pending_attach_capacity_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(V2SessionManagerError::Capacity);
        }
        let session = state.sessions.get_mut(&connection.session_id).ok_or(V2SessionManagerError::UnknownSession)?;
        let reservation = session
            .session
            .reserve_attach(connection.connection_id, path_epoch, key_epoch, now_ms)
            .map_err(map_lifecycle)?;
        let result = GatewayAttachReservation { session_id: connection.session_id, reservation };
        state.pending_connections.insert(
            connection.connection_id,
            PendingAttach {
                reservation: result,
                expires_at_ms: now_ms.saturating_add(self.config.pending_attach_ttl_ms),
            },
        );
        Ok(result)
    }

    pub(crate) fn commit_attach(&self, reservation: GatewayAttachReservation) -> Result<PathBinding, V2SessionManagerError> {
        let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
        if state.pending_connections.remove(&reservation.reservation.connection_id).map(|pending| pending.reservation) != Some(reservation) {
            return Err(V2SessionManagerError::UnknownAttach);
        }
        let session = state.sessions.get_mut(&reservation.session_id).ok_or(V2SessionManagerError::UnknownSession)?;
        let path = session.session.commit_attach(reservation.reservation).map_err(map_lifecycle)?;
        let path = session.session.set_path_state(path.path_id, PathState::Healthy).map_err(map_lifecycle)?;
        state.connections.insert(path.connection_id, (reservation.session_id, path.path_id, path.path_epoch, path.key_epoch));
        Ok(path)
    }

    /// Detaches exactly the path owned by this authenticated connection.
    pub(crate) fn detach_connection(
        &self,
        connection: AuthenticatedConnection,
        path_id: PathId,
        path_epoch: u64,
        now_ms: u64,
    ) -> Result<bool, V2SessionManagerError> {
        let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
        if state.authenticated_connections.get(&connection.connection_id) != Some(&connection.session_id) {
            return Err(V2SessionManagerError::UnknownConnection);
        }
        let Some((session_id, bound_path_id, bound_path_epoch, _)) = state.connections.get(&connection.connection_id).copied() else {
            return Ok(false);
        };
        if session_id != connection.session_id || bound_path_id != path_id || bound_path_epoch != path_epoch {
            return Err(V2SessionManagerError::BindingMismatch);
        }
        state.connections.remove(&connection.connection_id);
        let session = state.sessions.get_mut(&session_id).ok_or(V2SessionManagerError::UnknownSession)?;
        Ok(session.session.detach(path_id, connection.connection_id, path_epoch, now_ms))
    }

    /// Revalidates a listener-cached successful path attach before replaying a
    /// `PathAttached` reply. The capability, session, binding, and healthy
    /// path must still be current at the supplied deterministic clock value.
    pub(crate) fn validate_attached_path(
        &self,
        connection: AuthenticatedConnection,
        path_id: PathId,
        path_epoch: u64,
        key_epoch: u32,
        now_ms: u64,
    ) -> Result<(), V2SessionManagerError> {
        let mut cleanup = None;
        let result = {
            let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
            if state.authenticated_connections.get(&connection.connection_id) != Some(&connection.session_id) {
                return Err(V2SessionManagerError::UnknownConnection);
            }
            if state.connections.get(&connection.connection_id)
                != Some(&(connection.session_id, path_id, path_epoch, key_epoch))
            {
                return Err(V2SessionManagerError::BindingMismatch);
            }
            let Some(session) = state.sessions.get(&connection.session_id) else {
                return Err(V2SessionManagerError::UnknownSession);
            };
            if session.session.is_expired(now_ms) {
                cleanup = remove_session(&mut state, connection.session_id, SessionRemovalReason::Expired);
                Err(V2SessionManagerError::Expired)
            } else if now_ms.saturating_sub(session.last_activity_ms) >= self.config.idle_ttl_ms {
                cleanup = remove_session(&mut state, connection.session_id, SessionRemovalReason::Idle);
                Err(V2SessionManagerError::Idle)
            } else if session.session.state() != SessionState::Active
                || session.session.path(path_id).is_none_or(|path| path.state != PathState::Healthy)
            {
                Err(V2SessionManagerError::BindingMismatch)
            } else if let Some(session) = state.sessions.get_mut(&connection.session_id) {
                session.last_activity_ms = now_ms;
                Ok(())
            } else {
                Err(V2SessionManagerError::UnknownSession)
            }
        };
        if let Some(removal) = cleanup {
            self.record_removal(removal.reason);
            self.run_cleanup(removal);
        }
        result
    }

    /// Releases a listener-owned connection exactly once. A pending path is
    /// aborted; a committed path is detached. The authenticated capability is
    /// removed first, so concurrent close paths cannot repeat cleanup.
    pub(crate) fn close_connection(&self, connection: AuthenticatedConnection) -> Result<bool, V2SessionManagerError> {
        let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
        if state.authenticated_connections.remove(&connection.connection_id) != Some(connection.session_id) {
            return Ok(false);
        }
        if let Some(pending) = state.pending_connections.remove(&connection.connection_id) {
            if let Some(session) = state.sessions.get_mut(&pending.reservation.session_id) {
                return Ok(session.session.abort_attach(pending.reservation.reservation));
            }
            return Ok(false);
        }
        let Some((session_id, path_id, path_epoch, _)) = state.connections.remove(&connection.connection_id) else {
            return Ok(true);
        };
        let Some(session) = state.sessions.get_mut(&session_id) else {
            return Ok(false);
        };
        Ok(session.session.detach(path_id, connection.connection_id, path_epoch, session.last_activity_ms))
    }

    /// Validates all untrusted header routing fields before any flow, dedup,
    /// scheduler, address, or TUN resource is looked up.
    #[allow(dead_code)] // V2 data ingress begins in WP-300; keep binding validation isolated here.
    pub(crate) fn validate_ingress(
        &self,
        connection: AuthenticatedConnection,
        envelope: &V2Envelope,
        now_ms: u64,
    ) -> Result<ValidatedIngress, V2SessionManagerError> {
        if envelope.header.direction != Direction::ClientToGateway {
            return Err(V2SessionManagerError::InvalidDirection);
        }
        let mut cleanup = None;
        let result = {
            let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
            if state.authenticated_connections.get(&connection.connection_id) != Some(&connection.session_id) {
                return Err(V2SessionManagerError::UnknownConnection);
            }
            let Some((session_id, path_id, path_epoch, key_epoch)) = state.connections.get(&connection.connection_id).copied() else {
                return Err(V2SessionManagerError::UnknownConnection);
            };
            if envelope.header.session_id != session_id
                || envelope.header.path_id != path_id
                || envelope.header.path_epoch != path_epoch
            {
                return Err(V2SessionManagerError::BindingMismatch);
            }
            if envelope.header.key_epoch != key_epoch {
                return Err(V2SessionManagerError::StaleKeyEpoch);
            }
            let Some(session) = state.sessions.get(&session_id) else {
                return Err(V2SessionManagerError::UnknownSession);
            };
            if session.session.is_expired(now_ms) {
                cleanup = remove_session(&mut state, session_id, SessionRemovalReason::Expired);
                Err(V2SessionManagerError::Expired)
            } else if now_ms.saturating_sub(session.last_activity_ms) >= self.config.idle_ttl_ms {
                cleanup = remove_session(&mut state, session_id, SessionRemovalReason::Idle);
                Err(V2SessionManagerError::Idle)
            } else if session.session.state() != SessionState::Active
                || session.session.path(path_id).is_none_or(|path| path.state != PathState::Healthy)
            {
                Err(V2SessionManagerError::BindingMismatch)
            } else {
                if let Some(session) = state.sessions.get_mut(&session_id) {
                    session.last_activity_ms = now_ms;
                    Ok(ValidatedIngress { session_id, path_id, path_epoch, key_epoch })
                } else {
                    Err(V2SessionManagerError::UnknownSession)
                }
            }
        };
        if let Some(removal) = cleanup {
            self.record_removal(removal.reason);
            self.run_cleanup(removal);
        }
        result
    }

    pub fn begin_draining(&self, session_id: SessionId) -> Result<(), V2SessionManagerError> {
        let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
        state
            .sessions
            .get_mut(&session_id)
            .ok_or(V2SessionManagerError::UnknownSession)?
            .session
            .begin_draining()
            .map_err(map_lifecycle)
    }

    /// Removes a session once. Cleanup is invoked after releasing the lock.
    pub fn close(&self, session_id: SessionId) -> Result<bool, V2SessionManagerError> {
        let removal = {
            let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
            remove_session(&mut state, session_id, SessionRemovalReason::Closed)
        };
        if let Some(removal) = removal {
            self.record_removal(removal.reason);
            self.run_cleanup(removal);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Closes every path and authenticated connection for this session. The
    /// listener can invoke this only with its unforgeable authenticated handle.
    pub(crate) fn close_session(
        &self,
        connection: AuthenticatedConnection,
    ) -> Result<bool, V2SessionManagerError> {
        let removal = {
            let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
            if state.authenticated_connections.get(&connection.connection_id) != Some(&connection.session_id) {
                return Ok(false);
            }
            remove_session(&mut state, connection.session_id, SessionRemovalReason::Closed)
        };
        if let Some(removal) = removal {
            self.record_removal(removal.reason);
            self.run_cleanup(removal);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn sweep(&self, now_ms: u64) -> Result<usize, V2SessionManagerError> {
        let removals = {
            let mut state = self.state.lock().map_err(|_| V2SessionManagerError::Unavailable)?;
            let admissions_before = state.admissions.len();
            state.admissions.retain(|_, reservation| reservation.expires_at_ms > now_ms);
            self.metrics
                .admissions_expired
                .fetch_add((admissions_before - state.admissions.len()) as u64, Ordering::Relaxed);
            self.prune_pending_attaches(&mut state, now_ms);
            for session in state.sessions.values_mut() {
                session.session.prune_path_tombstones(now_ms);
            }
            let expired = state
                .sessions
                .iter()
                .filter_map(|(id, session)| {
                    if session.session.is_expired(now_ms) {
                        Some((*id, SessionRemovalReason::Expired))
                    } else if now_ms.saturating_sub(session.last_activity_ms) >= self.config.idle_ttl_ms {
                        Some((*id, SessionRemovalReason::Idle))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            expired
                .into_iter()
                .filter_map(|(id, reason)| remove_session(&mut state, id, reason))
                .collect::<Vec<_>>()
        };
        let count = removals.len();
        for removal in removals {
            self.record_removal(removal.reason);
            self.run_cleanup(removal);
        }
        Ok(count)
    }

    #[must_use]
    pub fn snapshot(&self) -> V2SessionManagerSnapshot {
        match self.state.lock() {
            Ok(state) => {
                let tombstones = state.sessions.values().map(|session| session.session.path_tombstones());
                let (path_tombstones, path_tombstones_expired, path_tombstones_capacity_evicted, path_epoch_history_entries) =
                    tombstones.fold((0, 0, 0, 0), |(entries, expired, evicted, history), snapshot| {
                        (
                            entries + snapshot.entries,
                            expired + snapshot.expired,
                            evicted + snapshot.capacity_evicted,
                            history + snapshot.epoch_history_entries,
                        )
                    });
                V2SessionManagerSnapshot {
                sessions: state.sessions.len(),
                admissions_pending: state.admissions.len(),
                paths: state.connections.len(),
                pending_attaches: state.pending_connections.len(),
                authenticated_connections: state.authenticated_connections.len(),
                maximum_sessions: self.config.maximum_sessions,
                maximum_paths_per_session: self.config.maximum_paths_per_session,
                maximum_pending_attaches: self.config.maximum_pending_attaches,
                maximum_authenticated_connections: self.maximum_authenticated_connections(),
                idle_ttl_ms: self.config.idle_ttl_ms,
                pending_attach_ttl_ms: self.config.pending_attach_ttl_ms,
                path_tombstones,
                maximum_path_tombstones_per_session: self.config.maximum_path_tombstones,
                path_tombstone_ttl_ms: self.config.path_tombstone_ttl_ms,
                path_tombstones_expired,
                path_tombstones_capacity_evicted,
                path_epoch_history_entries,
                maximum_path_epoch_history_per_session: self.config.maximum_path_epoch_history,
                admission_capacity_rejected: self.metrics.admission_capacity_rejected.load(Ordering::Relaxed),
                connection_capacity_rejected: self.metrics.connection_capacity_rejected.load(Ordering::Relaxed),
                pending_attach_capacity_rejected: self.metrics.pending_attach_capacity_rejected.load(Ordering::Relaxed),
                admissions_expired: self.metrics.admissions_expired.load(Ordering::Relaxed),
                pending_attaches_expired: self.metrics.pending_attaches_expired.load(Ordering::Relaxed),
                sessions_expired: self.metrics.sessions_expired.load(Ordering::Relaxed),
                sessions_idle: self.metrics.sessions_idle.load(Ordering::Relaxed),
                sessions_closed: self.metrics.sessions_closed.load(Ordering::Relaxed),
                }
            }
            Err(_) => V2SessionManagerSnapshot {
                sessions: 0,
                admissions_pending: 0,
                paths: 0,
                pending_attaches: 0,
                authenticated_connections: 0,
                maximum_sessions: self.config.maximum_sessions,
                maximum_paths_per_session: self.config.maximum_paths_per_session,
                maximum_pending_attaches: self.config.maximum_pending_attaches,
                maximum_authenticated_connections: self.maximum_authenticated_connections(),
                idle_ttl_ms: self.config.idle_ttl_ms,
                pending_attach_ttl_ms: self.config.pending_attach_ttl_ms,
                path_tombstones: 0,
                maximum_path_tombstones_per_session: self.config.maximum_path_tombstones,
                path_tombstone_ttl_ms: self.config.path_tombstone_ttl_ms,
                path_tombstones_expired: 0,
                path_tombstones_capacity_evicted: 0,
                path_epoch_history_entries: 0,
                maximum_path_epoch_history_per_session: self.config.maximum_path_epoch_history,
                admission_capacity_rejected: self.metrics.admission_capacity_rejected.load(Ordering::Relaxed),
                connection_capacity_rejected: self.metrics.connection_capacity_rejected.load(Ordering::Relaxed),
                pending_attach_capacity_rejected: self.metrics.pending_attach_capacity_rejected.load(Ordering::Relaxed),
                admissions_expired: self.metrics.admissions_expired.load(Ordering::Relaxed),
                pending_attaches_expired: self.metrics.pending_attaches_expired.load(Ordering::Relaxed),
                sessions_expired: self.metrics.sessions_expired.load(Ordering::Relaxed),
                sessions_idle: self.metrics.sessions_idle.load(Ordering::Relaxed),
                sessions_closed: self.metrics.sessions_closed.load(Ordering::Relaxed),
            },
        }
    }

    fn maximum_authenticated_connections(&self) -> usize {
        self.config.maximum_sessions.saturating_mul(self.config.maximum_paths_per_session)
    }

    fn next_connection_identity(&self) -> u64 {
        loop {
            let value = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
            if value != 0 {
                return value;
            }
        }
    }

    fn prune_pending_attaches(&self, state: &mut State, now_ms: u64) {
        let expired = state
            .pending_connections
            .iter()
            .filter_map(|(connection_id, pending)| (pending.expires_at_ms <= now_ms).then_some((*connection_id, pending.reservation)))
            .collect::<Vec<_>>();
        for (connection_id, reservation) in expired {
            state.pending_connections.remove(&connection_id);
            if let Some(session) = state.sessions.get_mut(&reservation.session_id) {
                session.session.abort_attach(reservation.reservation);
            }
            self.metrics.pending_attaches_expired.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_removal(&self, reason: SessionRemovalReason) {
        match reason {
            SessionRemovalReason::Expired => self.metrics.sessions_expired.fetch_add(1, Ordering::Relaxed),
            SessionRemovalReason::Idle => self.metrics.sessions_idle.fetch_add(1, Ordering::Relaxed),
            SessionRemovalReason::Closed => self.metrics.sessions_closed.fetch_add(1, Ordering::Relaxed),
        };
    }

    fn run_cleanup(&self, removal: SessionRemoval) {
        for cleanup in &self.cleanup {
            cleanup.remove_flows(removal);
            cleanup.remove_dedup(removal);
            cleanup.remove_scheduler(removal);
            cleanup.release_address(removal);
        }
    }
}

fn remove_session(state: &mut State, session_id: SessionId, reason: SessionRemovalReason) -> Option<SessionRemoval> {
    let mut session = state.sessions.remove(&session_id)?;
    let _ = session.session.begin_draining();
    session.session.close();
    state.connections.retain(|_, (bound_session, _, _, _)| *bound_session != session_id);
    state.pending_connections.retain(|_, pending| pending.reservation.session_id != session_id);
    state.authenticated_connections.retain(|_, bound_session| *bound_session != session_id);
    let admission = session.session.admission();
    Some(SessionRemoval {
        session_id,
        device_id: admission.device_id,
        organization_id: session.organization_id,
        reason,
    })
}

fn map_lifecycle(error: LifecycleError) -> V2SessionManagerError {
    match error {
        LifecycleError::Expired => V2SessionManagerError::Expired,
        LifecycleError::ConnectionAlreadyBound => V2SessionManagerError::ConnectionAlreadyBound,
        _ => V2SessionManagerError::Lifecycle,
    }
}

// ---------------------------------------------------------------------------
// Deterministic clock source for admission and sweep
// ---------------------------------------------------------------------------

/// Clock source for the periodic sweep and the admission listener. The two
/// time domains are deliberately separate:
///
/// - `monotonic_ms` is process-relative monotonic time and is the only time
///   source for TTL-based state (idle expiry, admission reservations,
///   pending-attach and path-tombstone deadlines).
/// - `unix_seconds` is the real wall clock since the Unix epoch and is used
///   only when validating time claims carried by admission tickets.
///
/// Mixing these domains is an error: a process-relative origin starts near
/// zero, so deriving unix time from it would make every ticket appear
/// expired (or valid) relative to claims expressed in real wall time.
pub trait Clock: Send + Sync {
    /// Current process-relative monotonic time in milliseconds.
    fn monotonic_ms(&self) -> u64;
    /// Current wall-clock time in seconds since the Unix epoch.
    fn unix_seconds(&self) -> u64;
}

/// Production clock. `monotonic_ms` is elapsed time since a process-relative
/// origin captured once at construction. `unix_seconds` reads `SystemTime`
/// directly against `UNIX_EPOCH`, so ticket claims are validated against the
/// real wall clock rather than a near-zero process origin.
#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock {
    origin: std::time::Instant,
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock {
    /// Captures the current monotonic instant as the process-relative origin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn monotonic_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Supervised periodic session expiry sweep
// ---------------------------------------------------------------------------

/// Configuration for the supervised periodic session expiry sweep.
///
/// The sweep interval is bounded between `min_interval_ms` and
/// `max_interval_ms`. The production trigger uses `min_interval_ms` as the
/// real tick frequency; the maximum is a validation bound that prevents
/// accidentally disabled sweeps. The sweep calls
/// [`V2SessionManager::sweep`] which is synchronous, deterministic, and
/// never holds the session-map lock across an await point.
///
/// Fields are private to prevent construction that bypasses validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSweepConfig {
    min_interval_ms: u64,
    max_interval_ms: u64,
}

impl SessionSweepConfig {
    /// Creates a sweep config with the given min and max interval. Returns
    /// `None` if the values are out of the valid range (`min >= 1`,
    /// `max >= min`, `max <= 3_600_000`).
    #[must_use]
    pub fn new(min_interval_ms: u64, max_interval_ms: u64) -> Option<Self> {
        if min_interval_ms < 1
            || max_interval_ms < min_interval_ms
            || max_interval_ms > 3_600_000
        {
            return None;
        }
        Some(Self {
            min_interval_ms,
            max_interval_ms,
        })
    }

    /// Convenience constructor for a fixed-interval sweep (min == max).
    #[must_use]
    pub fn fixed(interval_ms: u64) -> Option<Self> {
        Self::new(interval_ms, interval_ms)
    }

    /// Minimum interval between sweep invocations (monotonic milliseconds).
    #[must_use]
    pub fn min_interval_ms(&self) -> u64 {
        self.min_interval_ms
    }

    /// Maximum allowed interval between sweep invocations.
    #[must_use]
    pub fn max_interval_ms(&self) -> u64 {
        self.max_interval_ms
    }
}

/// Internal message sent through the sweep tick channel. Production ticks
/// carry no ack; manual (test) ticks carry a oneshot sender so the test
/// can await deterministic completion.
pub(crate) enum SweepTick {
    /// Run a sweep at the current clock time. Complete `ack` after processing
    /// if the sender is present (tests only).
    Sweep {
        ack: Option<tokio::sync::oneshot::Sender<()>>,
    },
    /// Shut down the sweep task.
    Shutdown,
}

/// Occupancy and outcome metrics for the periodic sweep, including the
/// capacity-1 coalescing tick queue (drops, queued ticks, and depth).
#[derive(Debug, Default)]
pub struct SweepMetrics {
    sweeps_completed: AtomicU64,
    sessions_reaped: AtomicU64,
    sweeps_empty: AtomicU64,
    ticks_queued: AtomicU64,
    ticks_dropped: AtomicU64,
    queue_depth: AtomicU64,
}

impl SweepMetrics {
    #[must_use]
    pub fn sweeps_completed(&self) -> u64 {
        self.sweeps_completed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn sessions_reaped(&self) -> u64 {
        self.sessions_reaped.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn sweeps_empty(&self) -> u64 {
        self.sweeps_empty.load(Ordering::Relaxed)
    }

    /// Ticks successfully enqueued into the capacity-1 sweep queue.
    #[must_use]
    pub fn ticks_queued(&self) -> u64 {
        self.ticks_queued.load(Ordering::Relaxed)
    }

    /// Ticks coalesced away because another tick was still pending. The
    /// queue is capacity 1, so a producer tick is dropped instead of forming
    /// a backlog; the pending tick runs with the latest clock value.
    #[must_use]
    pub fn ticks_dropped(&self) -> u64 {
        self.ticks_dropped.load(Ordering::Relaxed)
    }

    /// Last observed depth of the tick queue. The queue is capacity 1, so
    /// this gauge reads 0 or 1.
    #[must_use]
    pub fn queue_depth(&self) -> u64 {
        self.queue_depth.load(Ordering::Relaxed)
    }
}

impl PartialEq for SweepMetrics {
    fn eq(&self, other: &Self) -> bool {
        self.sweeps_completed() == other.sweeps_completed()
            && self.sessions_reaped() == other.sessions_reaped()
            && self.sweeps_empty() == other.sweeps_empty()
            && self.ticks_queued() == other.ticks_queued()
            && self.ticks_dropped() == other.ticks_dropped()
            && self.queue_depth() == other.queue_depth()
    }
}

impl Eq for SweepMetrics {}

/// Supervised periodic session expiry sweep for idle and expired admitted
/// sessions. The background task is owned exclusively by this struct and
/// cannot leak: the struct owns the `JoinHandle` for both the sweep task
/// and the production ticker task.
///
/// The task calls [`V2SessionManager::sweep`] at a rate driven by the
/// injected clock and tick channel. The sweep itself is synchronous and
/// never holds the session-map lock across an await point; the tick receive
/// and shutdown logic happen outside the map lock.
///
/// # Architecture
///
/// The sweep task owns the `mpsc::Receiver<SweepTick>` directly (no async
/// mutex), fed by a **capacity-1 bounded channel**. Production ticks arrive
/// from a tokio interval task whose `JoinHandle` is owned by this struct;
/// that task uses `try_send`, so a tick produced while a previous tick is
/// still pending is coalesced away and counted in
/// [`SweepMetrics::ticks_dropped`] rather than forming a backlog. Manual
/// ticks arrive from a [`test_support::ManualTriggerHandle`] sharing the
/// same channel.
///
/// # Shutdown
///
/// Call [`SupervisedSessionSweep::stop`] to abort the production ticker
/// (preventing new ticks), send `Shutdown` on the tick channel, and await
/// both task joins. Returns the final sweep metrics once both tasks have
/// exited. This method is idempotent.
pub struct SupervisedSessionSweep {
    handle: Option<tokio::task::JoinHandle<()>>,
    ticker_handle: Option<tokio::task::JoinHandle<()>>,
    tick_tx: tokio::sync::mpsc::Sender<SweepTick>,
    manager: Arc<V2SessionManager>,
    config: SessionSweepConfig,
    metrics: Arc<SweepMetrics>,
    #[allow(dead_code)] // Cloned into the spawned sweep task at construction.
    clock: Arc<dyn Clock>,
}

impl SupervisedSessionSweep {
    /// Spawns a supervised periodic sweep task using a production monotonic
    /// clock and a tokio interval ticker. The ticker and sweep task are both
    /// owned exclusively by the returned struct.
    pub fn spawn(
        manager: Arc<V2SessionManager>,
        config: SessionSweepConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        // Capacity-1 bounded channel: at most one tick may be pending. The
        // production ticker uses try_send, so a sweep still running when the
        // next interval fires coalesces into the pending tick instead of
        // growing an unbounded backlog.
        let (tick_tx, tick_rx) = tokio::sync::mpsc::channel::<SweepTick>(1);

        let metrics = Arc::new(SweepMetrics::default());
        let ticker_metrics = Arc::clone(&metrics);

        // Spawn the production ticker task. The sender is cloned so the
        // sweep struct retains its own for shutdown.
        let ticker_tx = tick_tx.clone();
        let interval = std::time::Duration::from_millis(config.min_interval_ms());
        let ticker_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                match ticker_tx.try_send(SweepTick::Sweep { ack: None }) {
                    Ok(()) => {
                        ticker_metrics.ticks_queued.fetch_add(1, Ordering::Relaxed);
                        ticker_metrics.queue_depth.store(1, Ordering::Relaxed);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // A tick is already pending: coalesce by dropping this
                        // one. The pending tick will run with the latest
                        // injected clock value.
                        ticker_metrics.ticks_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
        });

        let metrics_clone = Arc::clone(&metrics);
        let manager_clone = Arc::clone(&manager);
        let clock_clone = Arc::clone(&clock);

        let handle = tokio::spawn(async move {
            let mut tick_rx = tick_rx;
            while let Some(tick) = tick_rx.recv().await {
                // Capacity is 1, so consuming the tick has emptied the queue.
                metrics_clone.queue_depth.store(0, Ordering::Relaxed);
                match tick {
                    SweepTick::Shutdown => break,
                    SweepTick::Sweep { ack } => {
                        // Manager state unavailable or failed: attempt again
                        // on the next tick. Failures are bounded by the sweep
                        // interval and do not kill the supervised task.
                        if let Ok(count) = manager_clone.sweep(clock_clone.monotonic_ms()) {
                            metrics_clone.sweeps_completed.fetch_add(1, Ordering::Relaxed);
                            metrics_clone.sessions_reaped.fetch_add(
                                count as u64,
                                Ordering::Relaxed,
                            );
                            if count == 0 {
                                metrics_clone.sweeps_empty.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        if let Some(ack) = ack {
                            let _ = ack.send(());
                        }
                    }
                }
            }
        });

        Self {
            handle: Some(handle),
            ticker_handle: Some(ticker_handle),
            tick_tx,
            manager,
            config,
            metrics,
            clock,
        }
    }

    /// Test constructor: spawns a sweep task with a deterministic manual
    /// clock. No production ticker is created; tests drive ticks through the
    /// returned [`test_support::ManualTriggerHandle`].
    #[cfg(test)]
    pub fn spawn_with_manual(
        manager: Arc<V2SessionManager>,
        config: SessionSweepConfig,
        clock: Arc<test_support::ManualClock>,
    ) -> (Self, test_support::ManualTriggerHandle) {
        let (tick_tx, tick_rx) = tokio::sync::mpsc::channel::<SweepTick>(1);
        let metrics = Arc::new(SweepMetrics::default());
        let sweep_tx = tick_tx.clone();
        let trigger_handle = test_support::ManualTriggerHandle::new(
            tick_tx,
            Arc::clone(&clock),
            Arc::clone(&metrics),
        );

        let metrics_clone = Arc::clone(&metrics);
        let manager_clone = Arc::clone(&manager);
        // Move the original Arc<ManualClock> into Arc<dyn Clock> for the
        // sweep task and the lifecycle struct. The trigger handle already
        // received its own clone above.
        let clock_dyn: Arc<dyn Clock> = clock as Arc<dyn Clock>;
        let clock_for_task = Arc::clone(&clock_dyn);

        let handle = tokio::spawn(async move {
            let mut tick_rx = tick_rx;
            while let Some(tick) = tick_rx.recv().await {
                metrics_clone.queue_depth.store(0, Ordering::Relaxed);
                match tick {
                    SweepTick::Shutdown => break,
                    SweepTick::Sweep { ack } => {
                        if let Ok(count) = manager_clone.sweep(clock_for_task.monotonic_ms()) {
                            metrics_clone.sweeps_completed.fetch_add(1, Ordering::Relaxed);
                            metrics_clone.sessions_reaped.fetch_add(
                                count as u64,
                                Ordering::Relaxed,
                            );
                            if count == 0 {
                                metrics_clone.sweeps_empty.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        if let Some(ack) = ack {
                            let _ = ack.send(());
                        }
                    }
                }
            }
        });

        let sweep = Self {
            handle: Some(handle),
            ticker_handle: None,
            tick_tx: sweep_tx,
            manager,
            config,
            metrics,
            clock: clock_dyn,
        };
        (sweep, trigger_handle)
    }

    /// Signals the sweep task to shut down and waits for it to complete.
    /// Returns the final metrics snapshot after the task exits.
    ///
    /// The production ticker is aborted first so no new ticks arrive while
    /// draining. This method is idempotent: calling it after the task has
    /// already stopped returns the current metrics without error.
    pub async fn stop(&mut self) -> SweepMetrics {
        // Abort the production ticker first so no new ticks arrive.
        if let Some(handle) = self.ticker_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        // Signal the sweep task to shut down. The sweep task always drains
        // the capacity-1 queue, so awaiting send can wait for at most one
        // in-flight sweep to finish before the shutdown tick is queued.
        let _ = self.tick_tx.send(SweepTick::Shutdown).await;
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
        self.metrics_snapshot()
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> SweepMetrics {
        SweepMetrics {
            sweeps_completed: AtomicU64::new(self.metrics.sweeps_completed()),
            sessions_reaped: AtomicU64::new(self.metrics.sessions_reaped()),
            sweeps_empty: AtomicU64::new(self.metrics.sweeps_empty()),
            ticks_queued: AtomicU64::new(self.metrics.ticks_queued()),
            ticks_dropped: AtomicU64::new(self.metrics.ticks_dropped()),
            queue_depth: AtomicU64::new(self.metrics.queue_depth()),
        }
    }

    #[must_use]
    pub fn manager(&self) -> &Arc<V2SessionManager> {
        &self.manager
    }

    #[must_use]
    pub fn config(&self) -> SessionSweepConfig {
        self.config
    }
}

impl Drop for SupervisedSessionSweep {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.ticker_handle.take() {
            handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// V2 gateway lifecycle: production startup and shutdown
// ---------------------------------------------------------------------------

/// Production V2 gateway lifecycle. Owns the session manager, sweep task,
/// and monotonic clock. Constructs, spawns, and owns the supervised sweep
/// task, and provides a deterministic shutdown path.
///
/// The single `MonotonicClock` is shared between the sweep task and
/// the admission listener via [`clock`](Self::clock), providing one monotonic
/// time domain across the lifecycle. TTL-based state uses
/// [`monotonic_ms`](Clock::monotonic_ms); ticket validation uses real wall
/// time from [`unix_seconds`](Clock::unix_seconds).
///
/// This struct does not touch the V1 `main.rs` or `tunnel.rs`. It is the
/// V2 entry point for gateway session lifecycle management.
pub struct V2GatewayLifecycle {
    sweep: SupervisedSessionSweep,
    #[allow(dead_code)] // Shared clock; read by lifecycle callers and the V2 engine.
    clock: Arc<MonotonicClock>,
}

impl V2GatewayLifecycle {
    /// Starts the V2 gateway session lifecycle: creates the session manager,
    /// the shared monotonic clock, spawns the supervised sweep task, and
    /// returns the lifecycle handle.
    ///
    /// The caller owns the returned struct; dropping it aborts the sweep
    /// task. Call [`stop`](Self::stop) for a clean shutdown.
    pub fn start(
        manager_config: V2SessionManagerConfig,
        sweep_config: SessionSweepConfig,
        cleanup: Vec<Arc<dyn SessionCleanup>>,
    ) -> Result<Self, V2SessionManagerError> {
        let clock: Arc<MonotonicClock> = Arc::new(MonotonicClock::new());
        let manager = Arc::new(V2SessionManager::with_cleanup(manager_config, cleanup)?);
        let sweep =
            SupervisedSessionSweep::spawn(manager, sweep_config, Arc::clone(&clock) as Arc<dyn Clock>);
        Ok(Self { sweep, clock })
    }

    /// Starts the V2 gateway lifecycle with a pre-constructed session
    /// manager. Useful when the session manager needs shared ownership
    /// with other subsystems.
    pub fn start_with_manager(
        manager: Arc<V2SessionManager>,
        sweep_config: SessionSweepConfig,
    ) -> Self {
        let clock: Arc<MonotonicClock> = Arc::new(MonotonicClock::new());
        let sweep =
            SupervisedSessionSweep::spawn(manager, sweep_config, Arc::clone(&clock) as Arc<dyn Clock>);
        Self { sweep, clock }
    }

    /// Gracefully shuts down the sweep task and returns final metrics.
    pub async fn stop(&mut self) -> SweepMetrics {
        self.sweep.stop().await
    }

    /// Returns a snapshot of the session manager state.
    #[must_use]
    pub fn session_snapshot(&self) -> V2SessionManagerSnapshot {
        self.sweep.manager().snapshot()
    }

    /// Returns a reference to the session manager.
    #[must_use]
    pub fn manager(&self) -> &Arc<V2SessionManager> {
        self.sweep.manager()
    }

    /// Returns the shared monotonic clock. The admission listener and the
    /// sweep task both derive time from this clock, ensuring a single
    /// `AdmissionTime` domain across the lifecycle.
    #[must_use]
    pub fn clock(&self) -> Arc<MonotonicClock> {
        Arc::clone(&self.clock)
    }
}

#[cfg(test)]
mod test_support {
    use super::*;

    /// Deterministic clock for tests. `monotonic_ms` returns the value set
    /// by `set()`; `unix_seconds` is an independent settable domain used
    /// when a test must fix ticket-validity time. It defaults to the
    /// historical `initial_ms / 1000` so existing tests keep identical
    /// behavior; tests that validate tickets should call
    /// `set_unix_seconds` explicitly.
    #[derive(Debug)]
    pub struct ManualClock {
        now: AtomicU64,
        unix_seconds: AtomicU64,
    }

    impl ManualClock {
        pub fn new(initial_ms: u64) -> Self {
            Self {
                now: AtomicU64::new(initial_ms),
                unix_seconds: AtomicU64::new(initial_ms / 1000),
            }
        }

        pub fn set(&self, now_ms: u64) {
            self.now.store(now_ms, Ordering::Relaxed);
        }

        pub fn set_unix_seconds(&self, unix_seconds: u64) {
            self.unix_seconds.store(unix_seconds, Ordering::Relaxed);
        }
    }

    impl Clock for ManualClock {
        fn monotonic_ms(&self) -> u64 {
            self.now.load(Ordering::Relaxed)
        }

        fn unix_seconds(&self) -> u64 {
            self.unix_seconds.load(Ordering::Relaxed)
        }
    }

    /// Handle for sending deterministic ticks to the sweep task. Tests
    /// advance the clock and call `tick()` or `advance_and_tick()` which
    /// both await deterministic completion acknowledgement from the sweep
    /// task — no yield loops or real time. The shared tick channel has
    /// capacity 1; `tick_no_ack` returns whether the tick was actually
    /// queued so tests can assert coalescing behavior deterministically.
    pub struct ManualTriggerHandle {
        tick_tx: tokio::sync::mpsc::Sender<SweepTick>,
        clock: Arc<ManualClock>,
        metrics: Arc<SweepMetrics>,
    }

    impl ManualTriggerHandle {
        pub(crate) fn new(
            tick_tx: tokio::sync::mpsc::Sender<SweepTick>,
            clock: Arc<ManualClock>,
            metrics: Arc<SweepMetrics>,
        ) -> Self {
            Self { tick_tx, clock, metrics }
        }

        /// Advances the deterministic clock and sends one tick, waiting for
        /// the sweep task to complete processing. Fully deterministic: no
        /// real time elapses.
        pub async fn advance_and_tick(&self, new_ms: u64) {
            self.clock.set(new_ms);
            self.tick().await;
        }

        /// Sends a tick at the current clock value and waits for the sweep
        /// task to complete processing.
        pub async fn tick(&self) {
            let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
            if self.tick_tx.send(SweepTick::Sweep { ack: Some(ack_tx) }).await.is_ok() {
                self.metrics.ticks_queued.fetch_add(1, Ordering::Relaxed);
                self.metrics.queue_depth.store(1, Ordering::Relaxed);
            }
            let _ = ack_rx.await;
        }

        /// Advances the clock without sending a tick. Useful for tests that
        /// need to set time before a subsequent tick.
        pub fn advance_clock(&self, new_ms: u64) {
            self.clock.set(new_ms);
        }

        /// Sends a tick without waiting for completion acknowledgement.
        /// Returns `true` when the tick was queued. A `false` return means
        /// the capacity-1 queue already held a pending tick (coalesced/drop,
        /// counted in `ticks_dropped`) or the channel was closed, e.g. after
        /// the sweep owner was dropped.
        pub fn tick_no_ack(&self) -> bool {
            match self.tick_tx.try_send(SweepTick::Sweep { ack: None }) {
                Ok(()) => {
                    self.metrics.ticks_queued.fetch_add(1, Ordering::Relaxed);
                    self.metrics.queue_depth.store(1, Ordering::Relaxed);
                    true
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    self.metrics.ticks_dropped.fetch_add(1, Ordering::Relaxed);
                    self.metrics.queue_depth.store(1, Ordering::Relaxed);
                    false
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            }
        }

        #[must_use]
        pub fn clock(&self) -> &ManualClock {
            &self.clock
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sg_core::v2::{FlowId, PacketId, TrafficClass};
    use sg_protocol::v2::V2Header;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    const SESSION: SessionId = SessionId::from_bytes([1; 16]);
    const DEVICE: DeviceId = DeviceId::from_bytes([2; 16]);
    const ORGANIZATION: OrganizationId = OrganizationId::from_bytes([3; 16]);

    fn manager() -> V2SessionManager {
        V2SessionManager::new(V2SessionManagerConfig {
            maximum_sessions: 2,
            idle_ttl_ms: 10,
            maximum_paths_per_session: 2,
            maximum_pending_attaches: 2,
            pending_attach_ttl_ms: 5,
            maximum_path_epoch_history: 8,
            maximum_path_tombstones: 2,
            path_tombstone_ttl_ms: 5,
        })
        .unwrap()
    }

    fn activate(manager: &V2SessionManager) {
        let reservation = manager.reserve_admission(SESSION, DEVICE, ORGANIZATION, 100, 1).unwrap();
        manager.commit_admission(reservation, 1).unwrap();
    }

    fn connection(manager: &V2SessionManager) -> AuthenticatedConnection {
        manager.bind_authenticated_connection(SESSION, 1).unwrap()
    }

    fn envelope(path: PathBinding) -> V2Envelope {
        V2Envelope {
            header: V2Header {
                traffic_class: TrafficClass::Interactive,
                direction: Direction::ClientToGateway,
                session_id: SESSION,
                path_id: path.path_id,
                path_epoch: path.path_epoch,
                key_epoch: path.key_epoch,
                flow_id: FlowId::new(1),
                packet_id: PacketId::new(1),
            },
            payload: Bytes::from_static(b"packet"),
        }
    }

    #[test]
    fn admission_and_attachment_are_atomic_and_bounded() {
        let manager = manager();
        activate(&manager);
        let attached_connection = connection(&manager);
        let attach = manager.reserve_attach(attached_connection, 9, 1, 2).unwrap();
        let path = manager.commit_attach(attach).unwrap();
        let old_datagram = envelope(path);
        assert_eq!(path.state, PathState::Healthy);
        assert!(matches!(manager.reserve_attach(attached_connection, 10, 1, 2), Err(V2SessionManagerError::ConnectionAlreadyBound)));
        assert!(manager.detach_connection(attached_connection, path.path_id, path.path_epoch, 3).unwrap());
        assert!(!manager.detach_connection(attached_connection, path.path_id, path.path_epoch, 3).unwrap());
        assert_eq!(manager.snapshot().path_tombstones, 1);

        // Equal epochs may only attach on a fresh identifier while the old ID
        // is tombstoned. A delayed old packet cannot match that new binding.
        let replacement = manager.reserve_attach(attached_connection, 9, 1, 4).unwrap();
        let replacement = manager.commit_attach(replacement).unwrap();
        assert_ne!(replacement.path_id, path.path_id);
        assert_eq!(
            manager.validate_ingress(attached_connection, &old_datagram, 4),
            Err(V2SessionManagerError::BindingMismatch)
        );
        assert_eq!(manager.sweep(9).unwrap(), 0);
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.path_tombstones, 0);
        assert_eq!(snapshot.path_tombstones_expired, 1);
        assert_eq!(snapshot.maximum_path_tombstones_per_session, 2);
        assert_eq!(snapshot.path_tombstone_ttl_ms, 5);
        assert!(snapshot.path_epoch_history_entries >= 2);
    }

    #[test]
    fn concurrent_admission_has_one_owner() {
        let manager = Arc::new(manager());
        let first = Arc::clone(&manager);
        let second = Arc::clone(&manager);
        let one = thread::spawn(move || first.reserve_admission(SESSION, DEVICE, ORGANIZATION, 100, 1));
        let two = thread::spawn(move || second.reserve_admission(SESSION, DeviceId::from_bytes([9; 16]), ORGANIZATION, 100, 1));
        let results = [one.join().unwrap(), two.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| matches!(result, Err(V2SessionManagerError::OwnerMismatch))).count(), 1);
    }

    #[test]
    fn ingress_validates_binding_expiry_and_direction_before_resources() {
        let manager = manager();
        activate(&manager);
        let connection = connection(&manager);
        let attach = manager.reserve_attach(connection, 0x1_0000_0000, 9, 2).unwrap();
        let path = manager.commit_attach(attach).unwrap();
        let valid = envelope(path);
        assert!(manager.validate_ingress(connection, &valid, 2).is_ok());
        let mut wrong = valid.clone();
        wrong.header.path_epoch = 1;
        assert_eq!(manager.validate_ingress(connection, &wrong, 3), Err(V2SessionManagerError::BindingMismatch));
        wrong = valid.clone();
        wrong.header.key_epoch = 8;
        assert_eq!(manager.validate_ingress(connection, &wrong, 3), Err(V2SessionManagerError::StaleKeyEpoch));
        wrong = valid;
        wrong.header.direction = Direction::GatewayToClient;
        assert_eq!(manager.validate_ingress(connection, &wrong, 3), Err(V2SessionManagerError::InvalidDirection));
        assert_eq!(manager.validate_ingress(connection, &envelope(path), 100), Err(V2SessionManagerError::Expired));
        assert_eq!(manager.snapshot().sessions, 0);
    }

    #[test]
    fn commit_and_bind_rolls_back_a_new_session_when_connection_capacity_is_full() {
        let cleanup = Arc::new(RollbackCleanupProbe {
            calls: AtomicUsize::new(0),
            manager: std::sync::OnceLock::new(),
        });
        let manager = Arc::new(V2SessionManager::with_cleanup(
            V2SessionManagerConfig {
                maximum_sessions: 2,
                idle_ttl_ms: 10,
                maximum_paths_per_session: 1,
                maximum_pending_attaches: 2,
                pending_attach_ttl_ms: 5,
                maximum_path_epoch_history: 4,
                maximum_path_tombstones: 1,
                path_tombstone_ttl_ms: 5,
            },
            vec![cleanup.clone()],
        )
        .unwrap());
        assert!(cleanup.manager.set(Arc::clone(&manager)).is_ok());
        activate(&manager);
        let _first = connection(&manager);
        let _second = connection(&manager);
        let replacement = manager
            .reserve_admission(SessionId::from_bytes([4; 16]), DEVICE, ORGANIZATION, 100, 2)
            .unwrap();

        assert_eq!(
            manager.commit_admission_and_bind(replacement, 2),
            Err(V2SessionManagerError::ConnectionCapacity)
        );
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.sessions, 1);
        assert_eq!(snapshot.admissions_pending, 0);
        assert_eq!(snapshot.authenticated_connections, 2);
        assert_eq!(snapshot.sessions_closed, 1);
        assert_eq!(cleanup.calls.load(Ordering::Relaxed), 4);
    }

    struct CleanupCounter(AtomicUsize);

    impl SessionCleanup for CleanupCounter {
        fn remove_flows(&self, _removal: SessionRemoval) { self.0.fetch_add(1, Ordering::Relaxed); }
        fn remove_dedup(&self, _removal: SessionRemoval) { self.0.fetch_add(1, Ordering::Relaxed); }
        fn remove_scheduler(&self, _removal: SessionRemoval) { self.0.fetch_add(1, Ordering::Relaxed); }
        fn release_address(&self, _removal: SessionRemoval) { self.0.fetch_add(1, Ordering::Relaxed); }
    }

    struct CleanupProbe {
        calls: AtomicUsize,
        manager: std::sync::OnceLock<Arc<V2SessionManager>>,
    }

    impl CleanupProbe {
        fn after_removal(&self) {
            // Re-locking here proves cleanup was invoked only after the map
            // lock was released, and all session-owned state is already gone.
            let manager = self.manager.get().unwrap();
            let snapshot = manager.snapshot();
            assert_eq!(snapshot.sessions, 0);
            assert_eq!(snapshot.paths, 0);
            assert_eq!(snapshot.authenticated_connections, 0);
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl SessionCleanup for CleanupProbe {
        fn remove_flows(&self, _removal: SessionRemoval) { self.after_removal(); }
        fn remove_dedup(&self, _removal: SessionRemoval) { self.after_removal(); }
        fn remove_scheduler(&self, _removal: SessionRemoval) { self.after_removal(); }
        fn release_address(&self, _removal: SessionRemoval) { self.after_removal(); }
    }

    struct RollbackCleanupProbe {
        calls: AtomicUsize,
        manager: std::sync::OnceLock<Arc<V2SessionManager>>,
    }

    impl RollbackCleanupProbe {
        fn after_rollback(&self) {
            // Re-locking proves rollback cleanup happens after the atomic map
            // update releases the lock, with no orphaned admission or session.
            let snapshot = self.manager.get().unwrap().snapshot();
            assert_eq!(snapshot.sessions, 1);
            assert_eq!(snapshot.admissions_pending, 0);
            assert_eq!(snapshot.authenticated_connections, 2);
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl SessionCleanup for RollbackCleanupProbe {
        fn remove_flows(&self, _removal: SessionRemoval) { self.after_rollback(); }
        fn remove_dedup(&self, _removal: SessionRemoval) { self.after_rollback(); }
        fn remove_scheduler(&self, _removal: SessionRemoval) { self.after_rollback(); }
        fn release_address(&self, _removal: SessionRemoval) { self.after_rollback(); }
    }

    #[test]
    fn sweep_and_close_remove_once_and_cleanup_after_removal() {
        let cleanup = Arc::new(CleanupCounter(AtomicUsize::new(0)));
        let manager = V2SessionManager::with_cleanup(
            V2SessionManagerConfig {
                maximum_sessions: 1,
                idle_ttl_ms: 10,
                maximum_paths_per_session: 1,
                maximum_pending_attaches: 1,
                pending_attach_ttl_ms: 5,
                maximum_path_epoch_history: 4,
                maximum_path_tombstones: 1,
                path_tombstone_ttl_ms: 5,
            },
            vec![cleanup.clone()],
        )
        .unwrap();
        activate(&manager);
        assert_eq!(manager.sweep(11).unwrap(), 1);
        assert_eq!(cleanup.0.load(Ordering::Relaxed), 4);
        assert!(!manager.close(SESSION).unwrap());
        assert_eq!(cleanup.0.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn authenticated_close_drains_the_whole_session_and_invalidates_other_paths() {
        let cleanup = Arc::new(CleanupProbe {
            calls: AtomicUsize::new(0),
            manager: std::sync::OnceLock::new(),
        });
        let manager = Arc::new(
            V2SessionManager::with_cleanup(
                V2SessionManagerConfig {
                    maximum_sessions: 1,
                    idle_ttl_ms: 10,
                    maximum_paths_per_session: 2,
                    maximum_pending_attaches: 2,
                    pending_attach_ttl_ms: 5,
                    maximum_path_epoch_history: 4,
                    maximum_path_tombstones: 2,
                    path_tombstone_ttl_ms: 5,
                },
                vec![cleanup.clone()],
            )
            .unwrap(),
        );
        assert!(cleanup.manager.set(Arc::clone(&manager)).is_ok());
        activate(&manager);
        let closing_connection = connection(&manager);
        let other_connection = connection(&manager);
        let closing_path = manager.commit_attach(manager.reserve_attach(closing_connection, 9, 1, 2).unwrap()).unwrap();
        let other_path = manager.commit_attach(manager.reserve_attach(other_connection, 10, 2, 2).unwrap()).unwrap();
        let other_datagram = envelope(other_path);

        assert!(manager.close_session(closing_connection).unwrap());
        assert!(!manager.close_session(other_connection).unwrap());
        assert_eq!(cleanup.calls.load(Ordering::Relaxed), 4);
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.sessions, 0);
        assert_eq!(snapshot.paths, 0);
        assert_eq!(snapshot.authenticated_connections, 0);
        assert_eq!(snapshot.sessions_closed, 1);
        assert_eq!(
            manager.validate_ingress(other_connection, &other_datagram, 3),
            Err(V2SessionManagerError::UnknownConnection)
        );
        assert_eq!(
            manager.reserve_attach(other_connection, 11, 3, 3),
            Err(V2SessionManagerError::UnknownConnection)
        );
        assert!(!manager.close_connection(other_connection).unwrap());
        assert!(!manager.close_connection(closing_connection).unwrap());
        assert_eq!(cleanup.calls.load(Ordering::Relaxed), 4);
        assert_ne!(closing_path.path_id, other_path.path_id);
    }

    #[test]
    fn pending_attach_expires_and_snapshot_reports_all_bounds_and_removals() {
        let manager = manager();
        activate(&manager);
        let connection = connection(&manager);
        let attach = manager.reserve_attach(connection, 9, 1, 2).unwrap();
        assert_eq!(manager.snapshot().pending_attaches, 1);
        assert_eq!(manager.sweep(7).unwrap(), 0);
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.pending_attaches, 0);
        assert_eq!(snapshot.paths, 0);
        assert_eq!(snapshot.maximum_sessions, 2);
        assert_eq!(snapshot.maximum_paths_per_session, 2);
        assert_eq!(snapshot.maximum_pending_attaches, 2);
        assert_eq!(snapshot.maximum_authenticated_connections, 4);
        assert_eq!(snapshot.idle_ttl_ms, 10);
        assert_eq!(snapshot.pending_attach_ttl_ms, 5);
        assert_eq!(snapshot.pending_attaches_expired, 1);
        assert!(matches!(manager.commit_attach(attach), Err(V2SessionManagerError::UnknownAttach)));
        assert!(manager.close_connection(connection).unwrap());
        assert!(!manager.close_connection(connection).unwrap());
    }

    #[test]
    fn concurrent_attach_attach_detach_and_close_leave_no_duplicate_ownership() {
        let manager = Arc::new(manager());
        activate(&manager);
        let attached_connection = connection(&manager);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let first = Arc::clone(&manager);
        let first_barrier = Arc::clone(&barrier);
        let one = thread::spawn(move || {
            first_barrier.wait();
            first.reserve_attach(attached_connection, 9, 1, 2)
        });
        barrier.wait();
        let two = manager.reserve_attach(attached_connection, 10, 1, 2);
        let one = one.join().unwrap();
        let reservations = [one, two];
        assert_eq!(reservations.iter().filter(|result| result.is_ok()).count(), 1);
        let reservation = reservations.into_iter().find_map(Result::ok).unwrap();
        let path = manager.commit_attach(reservation).unwrap();

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let detaching = Arc::clone(&manager);
        let detaching_barrier = Arc::clone(&barrier);
        let detach = thread::spawn(move || {
            detaching_barrier.wait();
            detaching.detach_connection(attached_connection, path.path_id, path.path_epoch, 3)
        });
        barrier.wait();
        let replacing = manager.reserve_attach(attached_connection, 11, 1, 3);
        assert!(detach.join().unwrap().unwrap());
        if let Ok(replacing) = replacing {
            manager.commit_attach(replacing).unwrap();
        }
        assert!(manager.snapshot().paths <= 1);
        assert_eq!(manager.snapshot().pending_attaches, 0);

        let replacement_path = {
            let state = manager.state.lock().unwrap();
            state.connections.get(&attached_connection.connection_id).copied()
        };
        if let Some((_, path_id, path_epoch, _)) = replacement_path {
            assert!(manager.detach_connection(attached_connection, path_id, path_epoch, 3).unwrap());
        }

        let closing_connection = connection(&manager);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let attaching = Arc::clone(&manager);
        let attaching_barrier = Arc::clone(&barrier);
        let attach = thread::spawn(move || {
            attaching_barrier.wait();
            attaching.reserve_attach(closing_connection, 12, 1, 4)
        });
        barrier.wait();
        assert!(manager.close_connection(closing_connection).unwrap());
        if let Ok(reservation) = attach.join().unwrap() {
            assert!(matches!(manager.commit_attach(reservation), Err(V2SessionManagerError::UnknownAttach)));
        }
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.authenticated_connections, 1);
        assert_eq!(snapshot.paths, 0);
        assert_eq!(snapshot.pending_attaches, 0);
    }
}

// ---------------------------------------------------------------------------
// Supervised sweep deterministic tests
//
// The sweep task reads time exclusively through the injected `Clock` seam
// and receives ticks through the capacity-1 bounded `SweepTick` channel.
// Tests advance the clock and send ticks via `ManualTriggerHandle`; each
// tick carries a oneshot ack that the sweep completes after processing,
// eliminating yield loops and real-time dependencies. A buggy
// implementation that read real time instead of the injected clock cannot
// pass: the idle TTL is far larger than any real time that elapses during
// the test.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod supervised_sweep_tests {
    use super::*;
    use super::test_support::ManualClock;

    const IDLE_TTL_MS: u64 = 10_000;

    fn sweep_manager() -> V2SessionManager {
        V2SessionManager::new(V2SessionManagerConfig {
            maximum_sessions: 4,
            idle_ttl_ms: IDLE_TTL_MS,
            maximum_paths_per_session: 1,
            maximum_pending_attaches: 1,
            pending_attach_ttl_ms: 5,
            maximum_path_epoch_history: 4,
            maximum_path_tombstones: 1,
            path_tombstone_ttl_ms: 5,
        })
        .unwrap()
    }

    fn sweep_activate(mgr: &V2SessionManager, id: u8, at_ms: u64) {
        let session = SessionId::from_bytes([id; 16]);
        let device = DeviceId::from_bytes([id.wrapping_add(100); 16]);
        let org = OrganizationId::from_bytes([id.wrapping_add(200); 16]);
        let reservation = mgr
            .reserve_admission(session, device, org, 1_000_000, at_ms)
            .unwrap();
        mgr.commit_admission(reservation, at_ms).unwrap();
    }

    #[tokio::test]
    async fn supervised_sweep_reaps_idle_session_without_control_traffic() {
        let manager = Arc::new(sweep_manager());
        sweep_activate(&manager, 1, 1);

        let clock = Arc::new(ManualClock::new(1));
        let config = SessionSweepConfig::fixed(2).unwrap();
        let (mut sweep, trigger) = SupervisedSessionSweep::spawn_with_manual(
            Arc::clone(&manager),
            config,
            Arc::clone(&clock),
        );

        assert_eq!(manager.snapshot().sessions, 1);

        // First tick: clock is still well below the idle TTL, so the sweep
        // must NOT reap. tick() awaits deterministic completion.
        trigger.tick().await;
        assert_eq!(manager.snapshot().sessions, 1, "no reap before the clock advances");

        // Advance the injected clock past the idle TTL. The sweep task
        // observes the new clock value and completes processing.
        trigger.advance_and_tick(1 + IDLE_TTL_MS + 1).await;
        assert_eq!(manager.snapshot().sessions, 0);

        let metrics = sweep.stop().await;
        assert_eq!(metrics.sessions_reaped(), 1);
        assert!(metrics.sweeps_completed() >= 2);
    }

    #[tokio::test]
    async fn supervised_sweep_preserves_active_sessions_and_reaps_only_idle() {
        let manager = Arc::new(sweep_manager());
        // Both sessions are live admitted sessions with no control traffic.
        // Session 1 was last active at clock = 1; session 2 at clock = 5.
        sweep_activate(&manager, 1, 1);
        sweep_activate(&manager, 2, 5);

        let clock = Arc::new(ManualClock::new(1));
        let config = SessionSweepConfig::fixed(2).unwrap();
        let (mut sweep, trigger) = SupervisedSessionSweep::spawn_with_manual(
            Arc::clone(&manager),
            config,
            Arc::clone(&clock),
        );

        trigger.tick().await;
        assert_eq!(manager.snapshot().sessions, 2, "nothing is idle yet");

        // Session 1 idles out; session 2 (fresher last activity) survives.
        trigger.advance_and_tick(1 + IDLE_TTL_MS + 1).await;

        let snapshot = manager.snapshot();
        assert_eq!(snapshot.sessions, 1, "only the idle session is reaped");
        assert_eq!(snapshot.sessions_idle, 1);

        let metrics = sweep.stop().await;
        assert_eq!(metrics.sessions_reaped(), 1);
    }

    #[tokio::test]
    async fn supervised_sweep_stop_does_not_hang_and_is_idempotent() {
        let manager = Arc::new(sweep_manager());
        sweep_activate(&manager, 1, 1);

        let clock = Arc::new(ManualClock::new(1));
        let config = SessionSweepConfig::fixed(100).unwrap();
        let (mut sweep, _trigger) = SupervisedSessionSweep::spawn_with_manual(
            Arc::clone(&manager),
            config,
            Arc::clone(&clock),
        );

        // Stop before any tick fires; stop() awaits the join.
        let first = sweep.stop().await;
        assert_eq!(first.sessions_reaped(), 0);

        // Idempotent: a second stop is a no-op with identical metrics.
        let second = sweep.stop().await;
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn supervised_sweep_drop_is_safe_and_aborts_running_task() {
        let manager = Arc::new(sweep_manager());
        sweep_activate(&manager, 1, 1);

        // Clock stays below the TTL, so even a fully-run sweep would not
        // reap; this isolates the drop/abort path: no panic, no hang, and
        // manager state remains intact.
        let clock = Arc::new(ManualClock::new(1));
        let config = SessionSweepConfig::fixed(2).unwrap();
        let (sweep, _trigger) = SupervisedSessionSweep::spawn_with_manual(
            Arc::clone(&manager),
            config,
            Arc::clone(&clock),
        );
        drop(sweep);

        assert_eq!(manager.snapshot().sessions, 1);
    }

    #[tokio::test]
    async fn supervised_sweep_aborted_task_cannot_reap_after_owner_drop() {
        let manager = Arc::new(sweep_manager());
        sweep_activate(&manager, 1, 1);

        let clock = Arc::new(ManualClock::new(1));
        let config = SessionSweepConfig::fixed(1).unwrap();
        let (sweep, trigger) = SupervisedSessionSweep::spawn_with_manual(
            Arc::clone(&manager),
            config,
            Arc::clone(&clock),
        );
        // Drop the sole owner; Drop aborts the sweep task at the next poll.
        drop(sweep);

        // Advance the clock far past the idle TTL and send an ack-less tick.
        // The aborted task cannot process it. tick_no_ack avoids hanging on
        // a never-arriving ack.
        trigger.advance_clock(1 + IDLE_TTL_MS + 1);
        trigger.tick_no_ack();
        // Yield briefly to let the aborted task take effect (if it could).
        tokio::task::yield_now().await;
        assert_eq!(
            manager.snapshot().sessions,
            1,
            "a task aborted by owner drop must not reap sessions"
        );
    }

    #[tokio::test]
    async fn supervised_sweep_config_rejects_invalid_intervals() {
        assert!(SessionSweepConfig::new(0, 10).is_none());
        assert!(SessionSweepConfig::new(10, 5).is_none());
        assert!(SessionSweepConfig::new(1, 1).is_some());
        assert!(SessionSweepConfig::new(1, 100).is_some());
        assert!(SessionSweepConfig::fixed(0).is_none());
        assert!(SessionSweepConfig::fixed(5).is_some());
    }

    #[tokio::test]
    async fn manual_trigger_deterministic_reap_proves_clock_independence() {
        // This test proves the sweep is fully clock-independent by
        // performing multiple tick-advance cycles. Each tick sees the
        // injected clock value; real elapsed time is irrelevant.
        let manager = Arc::new(sweep_manager());
        sweep_activate(&manager, 1, 100);

        let clock = Arc::new(ManualClock::new(100));
        let config = SessionSweepConfig::fixed(1).unwrap();
        let (mut sweep, trigger) = SupervisedSessionSweep::spawn_with_manual(
            Arc::clone(&manager),
            config,
            Arc::clone(&clock),
        );

        // Tick at 100ms: idle is 0ms, well below TTL.
        trigger.tick().await;
        assert_eq!(manager.snapshot().sessions, 1);

        // Tick at 200ms: idle is 100ms, still below 10_000ms TTL.
        trigger.advance_and_tick(200).await;
        assert_eq!(manager.snapshot().sessions, 1);

        // Tick at 200ms again: clock hasn't moved.
        trigger.tick().await;
        assert_eq!(manager.snapshot().sessions, 1);

        // Jump directly to 20_000ms: idle is 19_900ms, well past TTL.
        trigger.advance_and_tick(20_000).await;
        assert_eq!(manager.snapshot().sessions, 0);

        let metrics = sweep.stop().await;
        assert_eq!(metrics.sessions_reaped(), 1);
        assert!(metrics.sweeps_completed() >= 4);
    }

    #[tokio::test]
    async fn lifecycle_start_and_stop_own_the_sweep() {
        let mut lifecycle = V2GatewayLifecycle::start(
            V2SessionManagerConfig {
                maximum_sessions: 2,
                idle_ttl_ms: 10,
                maximum_paths_per_session: 1,
                maximum_pending_attaches: 1,
                pending_attach_ttl_ms: 5,
                maximum_path_epoch_history: 4,
                maximum_path_tombstones: 1,
                path_tombstone_ttl_ms: 5,
            },
            SessionSweepConfig::fixed(1_000).unwrap(),
            Vec::new(),
        )
        .unwrap();

        let snapshot = lifecycle.session_snapshot();
        assert_eq!(snapshot.sessions, 0);

        // Verify the lifecycle owns a shared clock that the sweep uses.
        let clock = lifecycle.clock();
        assert!(clock.monotonic_ms() < 100, "clock should be process-fresh");

        let metrics = lifecycle.stop().await;
        assert_eq!(metrics.sessions_reaped(), 0);
    }

    #[tokio::test]
    async fn sweep_config_getters_return_constructed_values() {
        let config = SessionSweepConfig::new(50, 300).unwrap();
        assert_eq!(config.min_interval_ms(), 50);
        assert_eq!(config.max_interval_ms(), 300);

        let fixed = SessionSweepConfig::fixed(1_000).unwrap();
        assert_eq!(fixed.min_interval_ms(), 1_000);
        assert_eq!(fixed.max_interval_ms(), 1_000);
    }

    #[tokio::test]
    async fn clock_splits_monotonic_ttl_time_and_real_unix_ticket_time() {
        // Verifies the two Clock domains are independent: monotonic_ms is
        // process-relative (near zero at startup) while unix_seconds is real
        // wall time since the Unix epoch. A clock that derived unix time from
        // the process origin would return ~0 and break ticket validation.
        let clock = MonotonicClock::new();
        assert!(
            clock.monotonic_ms() < 100,
            "monotonic clock should be process-fresh"
        );
        let unix = clock.unix_seconds();
        assert!(
            unix >= 1_600_000_000,
            "unix_seconds must be real wall time (September 2020 or later), got {unix}"
        );
        assert!(clock.monotonic_ms() < 10_000);
    }

    #[tokio::test]
    async fn tick_queue_is_capacity_one_and_metrics_count_drops_and_depth() {
        // The sweep tick channel has capacity 1: a second producer tick
        // while one is pending is coalesced (dropped), never backlogged.
        // No real time elapses: tick_no_ack is synchronous and the sweep
        // task only runs at the explicit await points below.
        let manager = Arc::new(sweep_manager());
        let clock = Arc::new(ManualClock::new(1));
        let config = SessionSweepConfig::fixed(2).unwrap();
        let (mut sweep, trigger) = SupervisedSessionSweep::spawn_with_manual(
            Arc::clone(&manager),
            config,
            Arc::clone(&clock),
        );

        // First tick is queued and the queue reports depth 1.
        assert!(trigger.tick_no_ack());
        assert_eq!(sweep.metrics_snapshot().queue_depth(), 1);

        // Second tick while the first is still pending: coalesced drop with
        // no backlog growth.
        assert!(!trigger.tick_no_ack());
        let metrics = sweep.metrics_snapshot();
        assert_eq!(metrics.ticks_queued(), 1);
        assert_eq!(metrics.ticks_dropped(), 1);
        assert_eq!(metrics.queue_depth(), 1);

        // An ack-bearing tick waits for capacity, drains the pending tick,
        // and completes deterministically; the sweep task records depth 0
        // before acknowledging.
        trigger.tick().await;
        let metrics = sweep.metrics_snapshot();
        assert_eq!(metrics.ticks_queued(), 2);
        assert_eq!(metrics.ticks_dropped(), 1);
        assert_eq!(metrics.queue_depth(), 0);

        // Sweep is still fully functional after the coalesced tick.
        sweep_activate(&manager, 1, 1);
        trigger.advance_and_tick(1 + IDLE_TTL_MS + 1).await;
        assert_eq!(manager.snapshot().sessions, 0);

        let final_metrics = sweep.stop().await;
        assert_eq!(final_metrics.ticks_dropped(), 1);
        assert!(final_metrics.sessions_reaped() >= 1);
    }
}
