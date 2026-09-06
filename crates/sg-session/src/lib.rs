//! StreamGuard session core (spec section 15).
//!
//! A session is the logical tunnel between one device and the gateway. It
//! owns the per-session state shared by the client engine and the gateway:
//! the set of bound `PathTransport`s, the outbound `Sequencer` and the
//! inbound reorder/dedup window (spec 11.2 / 11.3).
//!
//! Wire identity: the envelope carries only the first 4 bytes of the
//! `SessionId` (spec 11.1). Gateway-side demultiplexing therefore keys on
//! that truncated id, so both ends must use ids whose trailing bytes are
//! constant. `session_id_from_wire` builds such an id; `SessionId::new()`
//! (full random UUID) is safe for local use but NOT for the wire.

use std::collections::HashMap;
use std::sync::Arc;

use sg_core::error::{Error, Result};
use sg_core::{PathId, Sequence, SessionId};
use sg_multipath::{ReorderWindow, Sequencer, default_reorder_window};
use sg_protocol::Envelope;
use sg_transport::PathTransport;

/// Builds a wire-safe session id from a 32-bit prefix (see module docs).
///
/// The envelope puts `bytes[0..4]` of the uuid on the wire and the decoder
/// zero-fills the tail, so any two ids with the same prefix collide at both
/// ends — exactly what gateway demultiplexing relies on.
pub fn session_id_from_wire(prefix: u32) -> SessionId {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&prefix.to_be_bytes());
    SessionId::from_bytes(b)
}

/// Per-session path and sequencing state. Used symmetrically by the client
/// (one session, several paths) and the gateway (many sessions, demuxed).
pub struct Session {
    session_id: SessionId,
    out_seq: Sequencer,
    in_window: ReorderWindow,
    paths: HashMap<PathId, Arc<dyn PathTransport>>,
    active_path: Option<PathId>,
}

impl Session {
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            out_seq: Sequencer::new(),
            in_window: default_reorder_window(),
            paths: HashMap::new(),
            active_path: None,
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Binds a transport to `path_id` (idempotent per path).
    pub fn add_path(&mut self, transport: Arc<dyn PathTransport>, path_id: PathId) -> Result<()> {
        if self.paths.contains_key(&path_id) {
            return Err(Error::transport(format!(
                "path {} already bound",
                path_id.get()
            )));
        }
        if self.active_path.is_none() {
            self.active_path = Some(path_id);
        }
        self.paths.insert(path_id, transport);
        Ok(())
    }

    pub fn has_path(&self, path_id: PathId) -> bool {
        self.paths.contains_key(&path_id)
    }

    pub fn path_ids(&self) -> impl Iterator<Item = PathId> + '_ {
        self.paths.keys().copied()
    }

    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Path selected for downlink (first bound in phase 1 active/standby).
    pub fn active_path(&self) -> Option<PathId> {
        self.active_path
    }

    pub fn set_active_path(&mut self, path_id: PathId) -> Result<()> {
        if !self.paths.contains_key(&path_id) {
            return Err(Error::transport(format!(
                "path {} not bound",
                path_id.get()
            )));
        }
        self.active_path = Some(path_id);
        Ok(())
    }

    /// Removes a bound path. Losing a path (connection death, link down) must
    /// not strand the session: if the removed path was active, the session
    /// falls back to the lowest remaining path id so the downlink keeps
    /// flowing on a standby. Returns true when the path was bound.
    pub fn remove_path(&mut self, path_id: PathId) -> bool {
        if self.paths.remove(&path_id).is_none() {
            return false;
        }
        if self.active_path == Some(path_id) {
            self.active_path = self.paths.keys().map(|p| p.get()).min().map(PathId::new);
        }
        true
    }

    /// Reserves the next outbound sequence number for this session.
    pub fn next_sequence(&mut self) -> Sequence {
        self.out_seq.next_sequence()
    }

    /// True when `seq` is new (non-duplicate) and may be passed up.
    pub fn accept_incoming(&mut self, seq: Sequence) -> bool {
        self.in_window.accept(seq)
    }

    /// Sends an envelope out the currently active path.
    pub async fn send(&mut self, envelope: Envelope) -> Result<()> {
        let path_id = self
            .active_path
            .ok_or_else(|| Error::transport("no active path bound"))?;
        self.send_on(path_id, envelope).await
    }

    /// Sends an envelope out a specific bound path.
    pub async fn send_on(&mut self, path_id: PathId, envelope: Envelope) -> Result<()> {
        let transport = self
            .paths
            .get(&path_id)
            .ok_or_else(|| Error::transport(format!("path {} not bound", path_id.get())))?;
        transport.send(envelope).await
    }

    pub fn path(&self, path_id: PathId) -> Option<&Arc<dyn PathTransport>> {
        self.paths.get(&path_id)
    }
}

/// Registry of sessions, keyed by wire-compatible `SessionId`.
///
/// The gateway keeps one of these and `get_or_create`s on every envelope;
/// the client keeps one session in it as well.
#[derive(Default)]
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create(&mut self, id: SessionId) -> &mut Session {
        self.sessions.entry(id).or_insert_with(|| Session::new(id))
    }

    pub fn session(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
    }

    pub fn session_mut(&mut self, id: SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(&id)
    }

    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    pub fn total_paths(&self) -> usize {
        self.sessions.values().map(Session::path_count).sum()
    }

    pub fn sessions(&self) -> impl Iterator<Item = &Session> + '_ {
        self.sessions.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sg_core::error::{Error, Result};
    use sg_protocol::{Envelope, PacketType, VERSION};
    use sg_transport::PathTransport;
    use async_trait::async_trait;

    /// Transport that never does anything (path bookkeeping tests only).
    #[derive(Debug)]
    struct NoopTransport;

    #[async_trait]
    impl PathTransport for NoopTransport {
        async fn send(&self, _env: Envelope) -> Result<()> {
            Ok(())
        }

        async fn recv(&self) -> Result<Envelope> {
            Err(Error::transport("noop transport cannot receive"))
        }

        fn path_id(&self) -> PathId {
            PathId::new(0)
        }
    }

    #[test]
    fn session_sequences_and_dedups() {
        let mut session = Session::new(session_id_from_wire(1));
        assert_eq!(session.next_sequence(), Sequence::new(0));
        assert_eq!(session.next_sequence(), Sequence::new(1));
        assert!(session.accept_incoming(Sequence::new(5)));
        assert!(!session.accept_incoming(Sequence::new(5)), "duplicate rejected");
    }

    #[test]
    fn set_active_path_rejects_unbound_path() {
        let mut session = Session::new(session_id_from_wire(1));
        assert_eq!(session.active_path(), None);
        assert!(session.set_active_path(PathId::new(9)).is_err());
    }

    #[test]
    fn removing_the_active_path_promotes_the_lowest_remaining() {
        let mut session = Session::new(session_id_from_wire(1));
        let a1 = PathId::new(1);
        let a2 = PathId::new(2);
        let a3 = PathId::new(3);
        let t1 = Arc::new(NoopTransport);
        let t2 = Arc::new(NoopTransport);
        let t3 = Arc::new(NoopTransport);
        session.add_path(t1, a1).unwrap();
        session.add_path(t2, a2).unwrap();
        session.add_path(t3, a3).unwrap();
        assert_eq!(session.active_path(), Some(a1), "first bound path is active");

        assert!(!session.remove_path(PathId::new(9)), "unbound path not removed");
        assert_eq!(session.path_count(), 3);

        assert!(session.remove_path(a1), "active path removed");
        assert_eq!(
            session.active_path(),
            Some(a2),
            "fallback promotes the lowest remaining path id"
        );
        assert_eq!(session.path_count(), 2);

        assert!(session.remove_path(a3));
        assert_eq!(session.active_path(), Some(a2));

        assert!(session.remove_path(a2));
        assert_eq!(session.active_path(), None, "no paths left -> no active path");
    }

    #[test]
    fn manager_get_or_create_shares_sessions() {
        let mut manager = SessionManager::new();
        let id = session_id_from_wire(7);
        assert_eq!(manager.count(), 0);
        assert!(manager.session(id).is_none());
        let s = manager.get_or_create(id);
        assert_eq!(s.session_id(), id);
        assert_eq!(manager.count(), 1);
        assert_eq!(manager.get_or_create(id).session_id(), id);
        assert_eq!(manager.count(), 1, "same id reuses the session");
        assert_eq!(manager.total_paths(), 0);
    }

    #[test]
    fn wire_session_id_survives_the_envelope() {
        let id = session_id_from_wire(0xde_ad_be_ef);
        let env = Envelope {
            version: VERSION,
            packet_type: PacketType::Data,
            flags: 0,
            path_id: PathId::new(1),
            session_id: id,
            sequence: Sequence::new(0),
            timestamp_ms: 0,
            payload: Bytes::new(),
        };
        let mut wire = bytes::BytesMut::with_capacity(64);
        let _ = env.encode(&mut wire).unwrap();
        let mut reader = wire.freeze();
        let decoded = Envelope::decode(&mut reader).unwrap();
        assert_eq!(decoded.session_id, id, "wire truncation is lossless for wire-safe ids");
    }
}