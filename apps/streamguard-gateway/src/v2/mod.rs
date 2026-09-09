//! V2 gateway components. These do not call the V1 tunnel, TUN, or session
//! map; wiring them to the V2 engine follows the V2 session-state packet.

pub mod admission;
pub mod listener;
