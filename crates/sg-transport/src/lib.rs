//! Secure client-to-gateway transport.
//!
//! Spec section 9.5: one independent QUIC connection per physical path in
//! phases 1-2, evolving to IETF Multipath QUIC in phase 3+. The concrete
//! QUIC stack (quinn/rustls) is introduced alongside the first real
//! tunnel milestone; this crate currently defines the seam that must stay
//! behind `sg-transport` so the scheduler never touches UDP directly.

/// V2 reliable-control framing over a caller-provided byte stream. This seam
/// deliberately does not create or open Quinn streams; WP-600 owns that work.
pub mod v2;

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

    /// Teardown: signals the peer the path is closed. Best-effort; scaffold
    /// transports may treat it as a no-op. Used to simulate or force a
    /// physical path loss so the health engine and scheduler can fail over.
    fn close(&self) {}

    /// Estimated achievable upload throughput in kilobits/sec (spec 13
    /// "estimated available throughput"). `None` when the transport cannot
    /// produce an estimate yet (e.g. mid-handshake, or a scaffold transport).
    /// Real QUIC implementations derive this from the congestion window and
    /// RTT (bandwidth-delay product); synthesized transports leave it as the
    /// default `None` (the health engine then reports kbps unmeasured).
    fn available_kbps(&self) -> Option<u64> {
        None
    }
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
