//! V2 client engine supervisor surface.
//!
//! WP-300 only: owns the blocking [`DriverTun`] boundary. Packet sequencing,
//! QUIC transport, and V1 client code live elsewhere and are untouched.

pub mod engine;
