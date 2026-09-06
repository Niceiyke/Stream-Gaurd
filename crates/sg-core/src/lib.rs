//! StreamGuard core types: shared IDs, sessions, configuration, errors.
//!
//! Owned by no other crate; every other crate depends on this one.

use serde::{Deserialize, Serialize};

pub mod error;
pub mod path_registry;

/// Identifies a StreamGuard device (one desktop/mobile install).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(uuid::Uuid);

/// Identifies a logical StreamGuard session at the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(uuid::Uuid);

/// Identifies a physical path within a session (0-255, see envelope `path_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathId(u8);

/// Monotonic per-session sequence number for tunneled packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Sequence(u64);

impl DeviceId {
    /// Generates a fresh random device id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn as_guid(&self) -> &uuid::Uuid {
        &self.0
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionId {
    /// Generates a fresh random session id.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn as_guid(&self) -> &uuid::Uuid {
        &self.0
    }

    /// Reconstructs a session id from a raw UUID byte array (wire decoding).
    pub fn from_bytes(b: [u8; 16]) -> Self {
        Self(uuid::Uuid::from_bytes(b))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl PathId {
    pub const fn new(id: u8) -> Self {
        Self(id)
    }

    pub const fn get(&self) -> u8 {
        self.0
    }
}

impl Sequence {
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }
}

impl Default for Sequence {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Maximum number of physical paths per session (envelope `path_id` is 1 byte).
pub const MAX_PATHS: usize = 256;

/// Service configuration consumed by the networking engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Global knobs shared across subsystems.
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub health: HealthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Gateway address the client connects to.
    pub gateway_host: String,
    /// Gateway UDP/QUIC port.
    pub gateway_port: u16,
    /// Logical session id (assigned by the client; gateway associates all paths).
    pub session_id: SessionId,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            gateway_host: String::from("gateway.streamguard.example"),
            gateway_port: 443,
            session_id: SessionId::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Health probe interval.
    pub probe_interval_ms: u64,
    /// Path considered degraded after this many consecutive failed probes.
    pub failure_threshold: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            probe_interval_ms: 1_000,
            failure_threshold: 2,
        }
    }
}