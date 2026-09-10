//! Pure, bounded V2 session and path lifecycle state.
//!
//! The gateway owns locking, admission capacity, and resource cleanup. This
//! module only owns one session's valid state transitions and has no transport,
//! packet, TUN, or async dependency.

use std::collections::{HashMap, VecDeque};

use sg_core::v2::{DeviceId, PathId, SessionId};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Pending,
    Active,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Connecting,
    Attached,
    Healthy,
    Suspect,
    Failed,
    Reconnecting,
}

/// An opaque authenticated transport identity assigned by the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2SessionConfig {
    pub maximum_paths: usize,
    /// Persistent, bounded epoch history. Reused IDs require both epochs to
    /// advance beyond this record for the lifetime of the session.
    pub maximum_path_epoch_history: usize,
    /// Recently detached IDs are not reused until this bounded quarantine
    /// expires, preventing delayed packets from aliasing a replacement path.
    pub maximum_path_tombstones: usize,
    pub path_tombstone_ttl_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathTombstoneSnapshot {
    pub entries: usize,
    pub capacity: usize,
    pub ttl_ms: u64,
    pub expired: u64,
    pub capacity_evicted: u64,
    pub epoch_history_entries: usize,
    pub epoch_history_capacity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    pub session_id: SessionId,
    pub device_id: DeviceId,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathBinding {
    pub path_id: PathId,
    pub path_epoch: u64,
    pub key_epoch: u32,
    pub connection_id: ConnectionId,
    pub state: PathState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachReservation {
    pub path_id: PathId,
    pub path_epoch: u64,
    pub key_epoch: u32,
    pub connection_id: ConnectionId,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("V2 session configuration is invalid")]
    InvalidConfiguration,
    #[error("V2 session admission is expired")]
    Expired,
    #[error("V2 session is not active")]
    InvalidSessionState,
    #[error("V2 path epoch is invalid")]
    InvalidPathEpoch,
    #[error("V2 key epoch is invalid")]
    InvalidKeyEpoch,
    #[error("V2 connection is already bound to a path")]
    ConnectionAlreadyBound,
    #[error("V2 path capacity is exhausted")]
    PathCapacity,
    #[error("V2 path identifier and epoch history capacity is exhausted")]
    PathIdentifierExhausted,
    #[error("V2 path reservation is unknown")]
    UnknownReservation,
    #[error("V2 path state transition is invalid")]
    InvalidPathState,
}

#[derive(Debug)]
struct PathEntry {
    binding: PathBinding,
    reserved: bool,
}

#[derive(Debug, Clone, Copy)]
struct PathEpochs {
    path_epoch: u64,
    key_epoch: u32,
}

#[derive(Debug, Clone, Copy)]
struct PathTombstone {
    expires_at_ms: u64,
}

/// One V2 session. A path ID and epoch are scoped to this session only.
#[derive(Debug)]
pub struct V2Session {
    admission: Admission,
    state: SessionState,
    maximum_paths: usize,
    paths: HashMap<PathId, PathEntry>,
    next_path_id: u16,
    path_epoch_history: HashMap<PathId, PathEpochs>,
    path_tombstones: HashMap<PathId, PathTombstone>,
    tombstone_order: VecDeque<PathId>,
    maximum_path_epoch_history: usize,
    maximum_path_tombstones: usize,
    path_tombstone_ttl_ms: u64,
    tombstones_expired: u64,
    tombstones_capacity_evicted: u64,
}

impl V2Session {
    pub fn new(config: V2SessionConfig, admission: Admission, now_ms: u64) -> Result<Self, LifecycleError> {
        if config.maximum_paths == 0
            || config.maximum_paths > usize::from(u16::MAX)
            || config.maximum_path_epoch_history < config.maximum_paths
            || config.maximum_path_epoch_history > usize::from(u16::MAX)
            || config.maximum_path_tombstones == 0
            || config.path_tombstone_ttl_ms == 0
            || admission.expires_at_ms == 0
        {
            return Err(LifecycleError::InvalidConfiguration);
        }
        if now_ms >= admission.expires_at_ms {
            return Err(LifecycleError::Expired);
        }
        Ok(Self {
            admission,
            state: SessionState::Pending,
            maximum_paths: config.maximum_paths,
            paths: HashMap::new(),
            next_path_id: 1,
            path_epoch_history: HashMap::new(),
            path_tombstones: HashMap::new(),
            tombstone_order: VecDeque::new(),
            maximum_path_epoch_history: config.maximum_path_epoch_history,
            maximum_path_tombstones: config.maximum_path_tombstones,
            path_tombstone_ttl_ms: config.path_tombstone_ttl_ms,
            tombstones_expired: 0,
            tombstones_capacity_evicted: 0,
        })
    }

    #[must_use]
    pub const fn admission(&self) -> Admission {
        self.admission
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub fn path(&self, path_id: PathId) -> Option<PathBinding> {
        self.paths.get(&path_id).map(|path| path.binding)
    }

    #[must_use]
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    #[must_use]
    pub fn path_tombstones(&self) -> PathTombstoneSnapshot {
        PathTombstoneSnapshot {
            entries: self.path_tombstones.len(),
            capacity: self.maximum_path_tombstones,
            ttl_ms: self.path_tombstone_ttl_ms,
            expired: self.tombstones_expired,
            capacity_evicted: self.tombstones_capacity_evicted,
            epoch_history_entries: self.path_epoch_history.len(),
            epoch_history_capacity: self.maximum_path_epoch_history,
        }
    }

    /// Expires detached-path quarantine using the gateway's monotonic clock.
    pub fn prune_path_tombstones(&mut self, now_ms: u64) {
        while let Some(path_id) = self.tombstone_order.front().copied() {
            let Some(tombstone) = self.path_tombstones.get(&path_id) else {
                self.tombstone_order.pop_front();
                continue;
            };
            if tombstone.expires_at_ms > now_ms {
                break;
            }
            self.tombstone_order.pop_front();
            self.path_tombstones.remove(&path_id);
            self.tombstones_expired = self.tombstones_expired.saturating_add(1);
        }
    }

    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.admission.expires_at_ms
    }

    pub fn activate(&mut self, now_ms: u64) -> Result<(), LifecycleError> {
        if self.is_expired(now_ms) {
            return Err(LifecycleError::Expired);
        }
        if self.state != SessionState::Pending {
            return Err(LifecycleError::InvalidSessionState);
        }
        self.state = SessionState::Active;
        Ok(())
    }

    pub fn begin_draining(&mut self) -> Result<(), LifecycleError> {
        if self.state != SessionState::Active {
            return Err(LifecycleError::InvalidSessionState);
        }
        self.state = SessionState::Draining;
        Ok(())
    }

    /// Returns true exactly once, when the session transitions to closed.
    pub fn close(&mut self) -> bool {
        if self.state == SessionState::Closed {
            return false;
        }
        self.state = SessionState::Closed;
        self.paths.clear();
        true
    }

    /// Reserves an uncommitted path. A connection can own at most one path.
    pub fn reserve_attach(
        &mut self,
        connection_id: ConnectionId,
        path_epoch: u64,
        key_epoch: u32,
        now_ms: u64,
    ) -> Result<AttachReservation, LifecycleError> {
        self.prune_path_tombstones(now_ms);
        if self.is_expired(now_ms) {
            return Err(LifecycleError::Expired);
        }
        if self.state != SessionState::Active {
            return Err(LifecycleError::InvalidSessionState);
        }
        if path_epoch == 0 {
            return Err(LifecycleError::InvalidPathEpoch);
        }
        if key_epoch == 0 {
            return Err(LifecycleError::InvalidKeyEpoch);
        }
        if self.paths.values().any(|path| path.binding.connection_id == connection_id) {
            return Err(LifecycleError::ConnectionAlreadyBound);
        }
        if self.paths.len() >= self.maximum_paths {
            return Err(LifecycleError::PathCapacity);
        }
        let path_id = self.allocate_path_id(path_epoch, key_epoch)
            .ok_or(LifecycleError::PathIdentifierExhausted)?;
        self.path_epoch_history.insert(path_id, PathEpochs { path_epoch, key_epoch });
        let reservation = AttachReservation { path_id, path_epoch, key_epoch, connection_id };
        self.paths.insert(
            path_id,
            PathEntry {
                binding: PathBinding {
                    path_id,
                    path_epoch,
                    key_epoch,
                    connection_id,
                    state: PathState::Connecting,
                },
                reserved: true,
            },
        );
        Ok(reservation)
    }

    pub fn commit_attach(&mut self, reservation: AttachReservation) -> Result<PathBinding, LifecycleError> {
        let path = self.paths.get_mut(&reservation.path_id).ok_or(LifecycleError::UnknownReservation)?;
        if !path.reserved
            || path.binding.connection_id != reservation.connection_id
            || path.binding.path_epoch != reservation.path_epoch
            || path.binding.key_epoch != reservation.key_epoch
        {
            return Err(LifecycleError::UnknownReservation);
        }
        path.reserved = false;
        path.binding.state = PathState::Attached;
        Ok(path.binding)
    }

    pub fn abort_attach(&mut self, reservation: AttachReservation) -> bool {
        self.paths.get(&reservation.path_id).is_some_and(|path| {
            path.reserved
                && path.binding.connection_id == reservation.connection_id
                && path.binding.path_epoch == reservation.path_epoch
                && path.binding.key_epoch == reservation.key_epoch
        }) && self.paths.remove(&reservation.path_id).is_some()
    }

    /// Detaching the same path repeatedly is deliberately idempotent.
    pub fn detach(&mut self, path_id: PathId, connection_id: ConnectionId, path_epoch: u64, now_ms: u64) -> bool {
        let Some(path) = self.paths.get(&path_id) else {
            return false;
        };
        if path.reserved
            || path.binding.connection_id != connection_id
            || path.binding.path_epoch != path_epoch
        {
            return false;
        }
        let epochs = PathEpochs {
            path_epoch: path.binding.path_epoch,
            key_epoch: path.binding.key_epoch,
        };
        self.insert_tombstone(path_id, epochs.path_epoch, epochs.key_epoch, now_ms);
        self.paths.remove(&path_id).is_some()
    }

    pub fn set_path_state(&mut self, path_id: PathId, next: PathState) -> Result<PathBinding, LifecycleError> {
        let path = self.paths.get_mut(&path_id).ok_or(LifecycleError::UnknownReservation)?;
        if path.reserved || !valid_path_transition(path.binding.state, next) {
            return Err(LifecycleError::InvalidPathState);
        }
        path.binding.state = next;
        Ok(path.binding)
    }

    fn allocate_path_id(&mut self, path_epoch: u64, key_epoch: u32) -> Option<PathId> {
        for _ in 0..u16::MAX {
            let path_id = PathId::new(self.next_path_id);
            self.next_path_id = if self.next_path_id == u16::MAX {
                1
            } else {
                self.next_path_id + 1
            };
            if self.paths.contains_key(&path_id) || self.path_tombstones.contains_key(&path_id) {
                continue;
            }
            match self.path_epoch_history.get(&path_id) {
                Some(previous)
                    if path_epoch <= previous.path_epoch || key_epoch <= previous.key_epoch => continue,
                Some(_) => return Some(path_id),
                None if self.path_epoch_history.len() < self.maximum_path_epoch_history => return Some(path_id),
                None => continue,
            }
        }
        None
    }

    fn insert_tombstone(&mut self, path_id: PathId, path_epoch: u64, key_epoch: u32, now_ms: u64) {
        while self.path_tombstones.len() >= self.maximum_path_tombstones {
            let Some(expired) = self.tombstone_order.pop_front() else {
                break;
            };
            if self.path_tombstones.remove(&expired).is_some() {
                self.tombstones_capacity_evicted = self.tombstones_capacity_evicted.saturating_add(1);
            }
        }
        self.path_epoch_history
            .entry(path_id)
            .and_modify(|epochs| {
                epochs.path_epoch = epochs.path_epoch.max(path_epoch);
                epochs.key_epoch = epochs.key_epoch.max(key_epoch);
            })
            .or_insert(PathEpochs { path_epoch, key_epoch });
        self.path_tombstones.insert(
            path_id,
            PathTombstone {
                expires_at_ms: now_ms.saturating_add(self.path_tombstone_ttl_ms),
            },
        );
        self.tombstone_order.push_back(path_id);
    }
}

fn valid_path_transition(current: PathState, next: PathState) -> bool {
    matches!(
        (current, next),
        (PathState::Connecting, PathState::Attached | PathState::Failed)
            | (PathState::Attached, PathState::Healthy | PathState::Failed)
            | (PathState::Healthy, PathState::Suspect | PathState::Failed)
            | (PathState::Suspect, PathState::Healthy | PathState::Failed)
            | (PathState::Failed, PathState::Reconnecting)
            | (PathState::Reconnecting, PathState::Connecting | PathState::Failed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission() -> Admission {
        Admission {
            session_id: SessionId::from_bytes([1; 16]),
            device_id: DeviceId::from_bytes([2; 16]),
            expires_at_ms: 100,
        }
    }

    fn config(maximum_paths: usize) -> V2SessionConfig {
        V2SessionConfig {
            maximum_paths,
            maximum_path_epoch_history: 8,
            maximum_path_tombstones: 2,
            path_tombstone_ttl_ms: 5,
        }
    }

    #[test]
    fn lifecycle_requires_activation_and_closes_once() {
        let mut session = V2Session::new(config(1), admission(), 1).unwrap();
        assert_eq!(session.state(), SessionState::Pending);
        assert!(matches!(session.reserve_attach(ConnectionId::new(1), 1, 1, 1), Err(LifecycleError::InvalidSessionState)));
        session.activate(1).unwrap();
        session.begin_draining().unwrap();
        assert!(session.close());
        assert!(!session.close());
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn attachment_is_bounded_and_transitions_through_every_path_state() {
        let mut session = V2Session::new(config(1), admission(), 1).unwrap();
        session.activate(1).unwrap();
        let reservation = session.reserve_attach(ConnectionId::new(7), 9, 1, 1).unwrap();
        let attached = session.commit_attach(reservation).unwrap();
        assert_eq!(attached.state, PathState::Attached);
        for state in [PathState::Healthy, PathState::Suspect, PathState::Failed, PathState::Reconnecting, PathState::Connecting, PathState::Attached] {
            session.set_path_state(reservation.path_id, state).unwrap();
        }
        assert!(matches!(session.reserve_attach(ConnectionId::new(8), 10, 1, 1), Err(LifecycleError::PathCapacity)));
        assert!(session.detach(reservation.path_id, ConnectionId::new(7), 9, 2));
        assert!(!session.detach(reservation.path_id, ConnectionId::new(7), 9, 2));
    }

    #[test]
    fn expired_admission_never_activates_or_attaches() {
        assert!(matches!(V2Session::new(config(1), admission(), 100), Err(LifecycleError::Expired)));
    }

    #[test]
    fn detached_paths_are_quarantined_and_reused_only_with_newer_epochs() {
        let mut session = V2Session::new(config(1), admission(), 1).unwrap();
        session.activate(1).unwrap();
        let first = session.reserve_attach(ConnectionId::new(1), 9, 7, 1).unwrap();
        session.commit_attach(first).unwrap();
        assert!(session.detach(first.path_id, ConnectionId::new(1), 9, 2));
        assert_eq!(session.path_tombstones().entries, 1);

        // A fresh ID is allocated while the detached ID remains quarantined,
        // even when the peer presents stale/equal epochs.
        let replacement = session.reserve_attach(ConnectionId::new(1), 9, 7, 3).unwrap();
        assert_ne!(replacement.path_id, first.path_id);
        session.commit_attach(replacement).unwrap();
        assert!(session.detach(replacement.path_id, ConnectionId::new(1), 9, 4));

        session.prune_path_tombstones(10);
        let snapshot = session.path_tombstones();
        assert_eq!(snapshot.entries, 0);
        assert_eq!(snapshot.expired, 2);
        assert_eq!(snapshot.capacity, 2);
        assert_eq!(snapshot.ttl_ms, 5);

        // Once the quarantine expires, an ID may be reused only if both
        // independently supplied epochs advance past its high-watermark.
        session.next_path_id = first.path_id.get();
        let stale = session.reserve_attach(ConnectionId::new(1), 9, 7, 10).unwrap();
        assert_ne!(stale.path_id, first.path_id);
        session.abort_attach(stale);
        session.next_path_id = first.path_id.get();
        let stale_path_epoch = session.reserve_attach(ConnectionId::new(1), 9, 8, 11).unwrap();
        assert_ne!(stale_path_epoch.path_id, first.path_id);
        session.abort_attach(stale_path_epoch);
        session.next_path_id = first.path_id.get();
        let stale_key_epoch = session.reserve_attach(ConnectionId::new(1), 10, 7, 12).unwrap();
        assert_ne!(stale_key_epoch.path_id, first.path_id);
        session.abort_attach(stale_key_epoch);
        session.next_path_id = first.path_id.get();
        let newer = session.reserve_attach(ConnectionId::new(1), 10, 8, 11).unwrap();
        assert_eq!(newer.path_id, first.path_id);

        let mut bounded = V2Session::new(
            V2SessionConfig {
                maximum_paths: 1,
                maximum_path_epoch_history: 8,
                maximum_path_tombstones: 1,
                path_tombstone_ttl_ms: 100,
            },
            admission(),
            1,
        )
        .unwrap();
        bounded.activate(1).unwrap();
        let one = bounded.reserve_attach(ConnectionId::new(1), 1, 1, 1).unwrap();
        bounded.commit_attach(one).unwrap();
        assert!(bounded.detach(one.path_id, ConnectionId::new(1), 1, 2));
        let two = bounded.reserve_attach(ConnectionId::new(1), 1, 1, 3).unwrap();
        bounded.commit_attach(two).unwrap();
        assert!(bounded.detach(two.path_id, ConnectionId::new(1), 1, 4));
        let bounded_snapshot = bounded.path_tombstones();
        assert_eq!(bounded_snapshot.entries, 1);
        assert_eq!(bounded_snapshot.capacity_evicted, 1);
    }
}
