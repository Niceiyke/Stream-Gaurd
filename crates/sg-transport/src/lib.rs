//! Secure client-to-gateway transport.
//!
//! Spec section 9.5: one independent QUIC connection per physical path in
//! phases 1-2, evolving to IETF Multipath QUIC in phase 3+. The concrete
//! QUIC stack (quinn/rustls) is introduced alongside the first real
//! tunnel milestone; this crate currently defines the seam that must stay
//! behind `sg-transport` so the scheduler never touches UDP directly.

use sg_core::{error::Result, PathId, SessionId};
use sg_protocol::Envelope;

/// Real QUIC single-path transport (feature `quic`).
#[cfg(feature = "quic")]
pub mod quic;

/// A single encrypted path to the gateway.
#[async_trait::async_trait]
pub trait PathTransport: Send + Sync {
    /// Sends one envelope on this path.
    async fn send(&self, envelope: Envelope) -> Result<()>;

    /// Receives the next envelope on this path.
    async fn recv(&self) -> Result<Envelope>;

    /// The path id this transport is bound to.
    fn path_id(&self) -> PathId;
}

/// Identifies a session at the gateway after the mTLS + token exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTicket {
    pub session_id: SessionId,
    /// Opaque gateway-issued ticket (JWT in the real implementation).
    pub token: String,
}

/// A transport layer owning multiple path transports for one session.
#[async_trait::async_trait]
pub trait TransportLayer: Send + Sync {
    /// Establishes the mTLS session and returns a session ticket.
    async fn connect(&self, session: SessionId) -> Result<SessionTicket>;

    /// Registers a new physical path with the session.
    async fn add_path(&self, ticket: &SessionTicket, path: PathId) -> Result<()>;
}

// Re-export so the async-trait macro name is convenient for downstream use.
pub use async_trait::async_trait;