//! Per-OS adapter, socket, route and firewall behavior (spec `sg-platform`).
//!
//! Platform matrix (spec `sg-platform` table):
//! - Windows: Wintun, socket binding via interface index, WFP policies
//! - Linux: /dev/net/tun, SO_BINDTODEVICE, policy routing
//! - macOS: utun, route sockets, NetworkExtension
//! - iOS: NE packet tunnel
//! - Android: VpnService
//!
//! This crate isolates everything OS-specific so the core crates stay
//! portable. The scaffold exposes the platform surface; concrete adapter
//! implementations land with each platform milestone.

use sg_core::error::{Error, Result};

pub mod gateway_net;

/// Named seam for platform-specific construction — this is where the real
/// adapter creation (Wintun, rtnetlink, utun, NE, VpnService) will live.
pub trait PlatformAdapter: Send + Sync {
    /// Human-readable platform identifier, e.g. "windows", "macos".
    fn name(&self) -> &'static str;

    /// Whether StreamGuard can currently claim the TUN adapter.
    fn can_create_tun(&self) -> bool;
}

/// Detects the current platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
    MacOs,
    Ios,
    Android,
    Unknown,
}

impl Os {
    pub fn current() -> Os {
        #[cfg(target_os = "windows")]
        {
            Os::Windows
        }
        #[cfg(target_os = "linux")]
        {
            Os::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Os::MacOs
        }
        #[cfg(target_os = "ios")]
        {
            Os::Ios
        }
        #[cfg(target_os = "android")]
        {
            Os::Android
        }
        #[cfg(not(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "android"
        )))]
        {
            Os::Unknown
        }
    }
}

/// Binds a UDP/QUIC socket to a specific NIC by interface index.
/// Platform implementations must hide the OS-specific mechanics (spec 8).
pub trait BindToInterface {
    fn bind_to_interface(&self, interface_index: u32) -> Result<()>;
}

/// Stub returned when the requested platform adapter is not implemented yet.
pub fn unavailable(what: &str) -> Error {
    Error::platform(format!("{what} not implemented on {}", Os::current().name()))
}

/// Adapter placeholder so callers can compile before the platform milestone.
pub struct NoopAdapter;

impl PlatformAdapter for NoopAdapter {
    fn name(&self) -> &'static str {
        Os::current().name()
    }

    fn can_create_tun(&self) -> bool {
        false
    }
}

impl Os {
    pub fn name(&self) -> &'static str {
        match self {
            Os::Windows => "windows",
            Os::Linux => "linux",
            Os::MacOs => "macos",
            Os::Ios => "ios",
            Os::Android => "android",
            Os::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_is_detectable() {
        assert!(!Os::current().name().is_empty());
    }

    #[test]
    fn noop_adapter_never_claims_tun() {
        assert!(!NoopAdapter.can_create_tun());
    }
}