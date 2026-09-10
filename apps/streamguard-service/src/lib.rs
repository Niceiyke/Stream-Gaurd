//! StreamGuard client-service library.
//!
//! The binary (`main.rs`) handles startup/TUN setup; this library owns the
//! client engine (step 6): orchestrating the per-session `SessionManager`,
//! one QUIC `PathTransport` per physical path, and the uplink/downlink
//! loops that bridge local host traffic into the tunnel.

pub mod client;
pub mod ipc;
pub mod status;
/// V2 client engine supervisor (REBUILD WP-300). Isolated from the V1 client
/// engine until cutover; owns the blocking TUN driver boundary only.
pub mod v2;