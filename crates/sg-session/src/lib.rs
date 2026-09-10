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
use std::time::{Duration, Instant};

use bytes::Bytes;
use sg_core::error::{Error, Result};
use sg_core::{PathId, Sequence, SessionId};
use sg_multipath::{Decision, ReorderBuffer, Sequencer, WeightedBondingScheduler};
use sg_protocol::Envelope;
use sg_transport::PathTransport;

/// Production V2 lifecycle state is isolated from the experimental V1 session
/// and its session-global reorder queue.
pub mod v2;

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

/// Adopted phase-3 downlink-bonding state (spec 12 Phase 3, gateway side).
///
/// The client owns the authoritative health snapshot and *publishes* the
/// normalized per-path weights via `Control::WeightSet`; the gateway mirrors
/// that distribution for its downlink egress with the same smooth-WRR
/// scheduler the client's uplink uses. `advertised_at` arms a TTL so a stale
/// advertisement (client died mid-session, weights no longer refreshed)
/// deterministically falls back to the phase-1 `active_path`.
#[derive(Debug)]
struct DownlinkBonds {
    scheduler: WeightedBondingScheduler,
    expires_at: Instant,
}

/// Per-session path and sequencing state. Used symmetrically by the client
/// (one session, several paths) and the gateway (many sessions, demuxed).
pub struct Session {
    session_id: SessionId,
    out_seq: Sequencer,
    reorder: ReorderBuffer,
    paths: HashMap<PathId, Arc<dyn PathTransport>>,
    active_path: Option<PathId>,
    downlink: Option<DownlinkBonds>,
}

impl Session {
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            out_seq: Sequencer::new(),
            reorder: ReorderBuffer::new(128),
            paths: HashMap::new(),
            active_path: None,
            downlink: None,
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
    ///
    /// Adopted downlink weights are pruned in lockstep — a dead path must
    /// never be scheduled by the phase-3 mirror — and if no bound path keeps
    /// weight the whole bond is dropped and the downlink falls back to
    /// `active_path`.
    pub fn remove_path(&mut self, path_id: PathId) -> bool {
        if self.paths.remove(&path_id).is_none() {
            return false;
        }
        if self.active_path == Some(path_id) {
            self.active_path = self.paths.keys().map(|p| p.get()).min().map(PathId::new);
        }
        if let Some(bonds) = self.downlink.as_mut() {
            let kept: Vec<(u8, f32)> = bonds
                .scheduler
                .normalized_weights()
                .into_iter()
                .filter(|(p, _)| self.paths.contains_key(&PathId::new(*p)))
                .collect();
            if kept.is_empty() {
                self.downlink = None;
            } else {
                bonds.scheduler.adopt_weights(kept);
            }
        }
        true
    }

    /// Reserves the next outbound sequence number for this session.
    pub fn next_sequence(&mut self) -> Sequence {
        self.out_seq.next_sequence()
    }

    /// Feeds one inbound (sequence, payload) into the session's reorder
    /// buffer; returns the payloads that became deliverable in sequence
    /// order (spec 11.2: the gateway reorders before injection into TUN).
    pub fn enqueue_incoming(
        &mut self,
        seq: Sequence,
        payload: Bytes,
    ) -> sg_multipath::ReorderOutcome {
        self.reorder.deliver(seq, payload)
    }

    pub fn pending_incoming(&self) -> usize {
        self.reorder.pending()
    }

    // -- Phase-3 downlink bonding mirror (spec 12 Phase 3) ----------------

    /// Adopts the client's advertised downlink weights for `ttl` (a stale
    /// advertisement deterministically falls back to `active_path`). Entries
    /// for unbound paths are ignored — a `WeightSet` can arrive racing an
    /// eviction — and the surviving vector is re-normalized defensively.
    /// Returns the number of bound, positive-weight entries adopted
    /// (0 when nothing was applied).
    pub fn adopt_downlink_weights(&mut self, weights: Vec<(PathId, f32)>, ttl: Duration) -> usize {
        let adopted: Vec<(u8, f32)> = weights
            .into_iter()
            .filter(|(p, w)| self.paths.contains_key(p) && w.is_finite() && *w > 0.0)
            .map(|(p, w)| (p.get(), w))
            .collect();
        let n = adopted.len();
        if n > 0 {
            let bonds = self.downlink.get_or_insert_with(|| DownlinkBonds {
                scheduler: WeightedBondingScheduler::default(),
                expires_at: Instant::now(),
            });
            bonds.scheduler.adopt_weights(adopted);
            bonds.expires_at = Instant::now() + ttl;
        } else {
            self.downlink = None;
        }
        n
    }

    /// True while the last adopted weight set is still fresh. The client
    /// re-advertises on every material change; the TTL is the safety valve
    /// that reverts the gateway to phase-1 active/standby when the client
    /// goes quiet.
    pub fn downlink_weights_fresh(&self) -> bool {
        self.downlink
            .as_ref()
            .is_some_and(|b| b.expires_at > Instant::now())
    }

    /// Smooth-WRR egress decision from the adopted downlink weights (the
    /// same `WeightedBondingScheduler::decide` the client's uplink runs),
    /// or `None` when no fresh weight set exists — the caller then falls
    /// back to `active_path` exactly as before the advertisement.
    pub fn downlink_decide(&mut self) -> Option<PathId> {
        let bonds = self.downlink.as_mut()?;
        if bonds.expires_at <= Instant::now() {
            self.downlink = None;
            return None;
        }
        match bonds.scheduler.decide() {
            Decision::Send { path } => Some(PathId::new(path)),
            Decision::Skip | Decision::Duplicate { .. } => None,
        }
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
    fn session_sequences_and_reorders_inbound() {
        let mut session = Session::new(session_id_from_wire(1));
        assert_eq!(session.next_sequence(), Sequence::new(0));
        assert_eq!(session.next_sequence(), Sequence::new(1));

        let out = session.enqueue_incoming(Sequence::new(5), Bytes::from_static(b"five"));
        assert!(out.buffered, "out-of-order seq held awaiting seq0..4");
        assert!(out.delivered.is_empty());
        assert_eq!(session.pending_incoming(), 1);

        let dup = session.enqueue_incoming(Sequence::new(5), Bytes::from_static(b"five-bis"));
        assert!(dup.dropped, "duplicate rejected");

        let o = session.enqueue_incoming(Sequence::new(0), Bytes::from_static(b"zero"));
        assert_eq!(o.delivered.len(), 1, "only seq0 is contiguous yet");
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

    // -----------------------------------------------------------------------
    // Phase-3 downlink bonding mirror (spec 12 Phase 3)
    // -----------------------------------------------------------------------

    #[test]
    fn adopted_weights_decide_and_prune_with_path_removal() {
        let mut session = Session::new(session_id_from_wire(1));
        let a1 = PathId::new(1);
        let a2 = PathId::new(2);
        session.add_path(Arc::new(NoopTransport), a1).unwrap();
        session.add_path(Arc::new(NoopTransport), a2).unwrap();

        assert!(!session.downlink_weights_fresh(), "no advertisement yet");
        assert_eq!(session.downlink_decide(), None, "no bond -> fall back to active");
        assert_eq!(session.active_path(), Some(a1), "fallback path is the active one");

        // Adopt an asymmetric 3:1 distribution; the mirror schedules both.
        let adopted = session.adopt_downlink_weights(
            vec![(a1, 0.75), (a2, 0.25), (PathId::new(9), 1.0)],
            Duration::from_secs(60),
        );
        assert_eq!(adopted, 2, "unbound path 9 is filtered out");
        assert!(session.downlink_weights_fresh());

        let mut hits = [0u64; 2];
        for _ in 0..12 {
            match session.downlink_decide() {
                Some(p) if p == a1 => hits[0] += 1,
                Some(p) if p == a2 => hits[1] += 1,
                other => panic!("unexpected downlink decision {other:?}"),
            }
        }
        assert!(hits[0] > 0 && hits[1] > 0, "both paths receive downlink work");
        assert!(
            (hits[0] as f32 / hits[1] as f32 - 3.0).abs() <= 0.5,
            "empirical ratio tracks the adopted 3:1 weights: {hits:?}"
        );

        // Evict the high-weight path: the mirror must not schedule it again.
        assert!(session.remove_path(a1));
        assert_eq!(
            session.active_path(),
            Some(a2),
            "active falls back to the lowest remaining"
        );
        for _ in 0..8 {
            assert_eq!(
                session.downlink_decide(),
                Some(a2),
                "pruned bond schedules only the surviving path"
            );
        }

        // Evict the last weighted path: the bond collapses and the callers
        // fall back to active_path.
        assert!(session.remove_path(a2));
        assert_eq!(session.downlink_decide(), None);
    }

    #[test]
    fn stale_weights_are_dropped_and_re_adopted() {
        let mut session = Session::new(session_id_from_wire(1));
        let a1 = PathId::new(1);
        session.add_path(Arc::new(NoopTransport), a1).unwrap();

        // Adopt with a TTL that is already expired: nothing is scheduled.
        session.adopt_downlink_weights(vec![(a1, 1.0)], Duration::ZERO);
        assert!(!session.downlink_weights_fresh());
        assert_eq!(session.downlink_decide(), None);

        // A fresh advertisement re-arms the mirror.
        session.adopt_downlink_weights(vec![(a1, 1.0)], Duration::from_secs(60));
        assert!(session.downlink_weights_fresh());
        assert_eq!(session.downlink_decide(), Some(a1));
    }

    #[test]
    fn adopt_replaces_the_previous_distribution() {
        let mut session = Session::new(session_id_from_wire(1));
        let a1 = PathId::new(1);
        let a2 = PathId::new(2);
        session.add_path(Arc::new(NoopTransport), a1).unwrap();
        session.add_path(Arc::new(NoopTransport), a2).unwrap();

        session.adopt_downlink_weights(vec![(a1, 1.0), (a2, 0.0)], Duration::from_secs(60));
        assert_eq!(session.downlink_decide(), Some(a1), "zero-weight entry dropped");

        session.adopt_downlink_weights(vec![(a2, 1.0)], Duration::from_secs(60));
        assert_eq!(session.downlink_decide(), Some(a2), "re-adoption replaces the bond");
    }
}
