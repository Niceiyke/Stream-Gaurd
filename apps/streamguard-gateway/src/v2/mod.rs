//! V2 gateway components. These do not call the V1 tunnel, TUN, or session
//! map; wiring them to the V2 engine follows the V2 session-state packet.

pub mod address_pool;
pub mod admission;
pub mod config;
pub mod engine;
pub mod forwarding;
pub mod listener;
pub mod persistence;
pub mod replay;
pub mod runtime;
pub mod session_manager;
pub mod setup;
