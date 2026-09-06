//! StreamGuard path registry (gateway side).
//!
//! Associates authenticated physical paths with the same logical session
//! (spec section 10). Each path is a separate QUIC connection in phases
//! 1-2; the registry lets the gateway map any inbound path back to its
//! session and sequence/deduplicate at the boundary.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::{PathId, SessionId};

/// Gateway-side association of paths to sessions.
#[derive(Debug, Default)]
pub struct PathRegistry {
    sessions: HashMap<SessionId, Vec<PathId>>,
}

impl PathRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a session with no paths yet.
    pub fn register(&mut self, session: SessionId) {
        self.sessions.entry(session).or_default();
    }

    /// Adds a path to an existing session.
    pub fn add_path(&mut self, session: SessionId, path: PathId) -> Result<()> {
        let paths = self
            .sessions
            .get_mut(&session)
            .ok_or_else(|| Error::protocol("unknown session"))?;
        if !paths.contains(&path) {
            paths.push(path);
        }
        Ok(())
    }

    /// Paths currently bound to a session.
    pub fn paths_for(&self, session: SessionId) -> &[PathId] {
        self.sessions
            .get(&session)
            .map(|p| p.as_slice())
            .unwrap_or(&[])
    }

    /// Removes a session entirely (shutdown / revocation).
    pub fn remove(&mut self, session: SessionId) {
        self.sessions.remove(&session);
    }
}