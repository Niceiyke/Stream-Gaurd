//! StreamGuard gateway library.
//!
//! The binary (`main.rs`) handles startup/TUN/NAT setup; this library owns
//! the tunnel service (step 5): accepting QUIC paths, demultiplexing
//! sessions and bridging host IP traffic through the virtual NIC.

pub mod tunnel;
/// V2 admission is isolated from the experimental V1 tunnel until cutover.
pub mod v2;
