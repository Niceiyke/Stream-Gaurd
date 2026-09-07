//! StreamGuard client-service library.
//!
//! The binary (`main.rs`) handles startup/TUN setup; this library owns the
//! client engine (step 6): orchestrating the per-session `SessionManager`,
//! one QUIC `PathTransport` per physical path, and the uplink/downlink
//! loops that bridge local host traffic into the tunnel.

pub mod client;
pub mod ipc;
pub mod status;