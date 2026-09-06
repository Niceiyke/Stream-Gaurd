//! Physical-interface discovery and bound-path creation.
//!
//! Mirrors the `Interface` representation from the spec (section 7) and the
//! path-binding abstraction from section 8.

use sg_core::{error::Result, PathId};

/// Interface type where detectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InterfaceKind {
    Ethernet,
    Wifi,
    Cellular,
    UsbTether,
    Virtual,
    Unknown,
}

/// Operational state of an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InterfaceState {
    Up,
    Down,
    Dormant,
}

/// A discovered physical interface.
///
/// Note (spec 7): do not assume a "cellular" path always reports as
/// cellular — phone tethering may appear as Wi-Fi or Ethernet.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Interface {
    /// Stable per-OS interface identifier.
    pub id: String,
    pub name: String,
    pub kind: InterfaceKind,
    /// IPv4/IPv6 addresses assigned.
    pub addresses: Vec<std::net::IpAddr>,
    pub mtu: u32,
    pub state: InterfaceState,
    /// Default gateway on this interface, if any.
    pub gateway: Option<std::net::IpAddr>,
    /// RX/TX byte counters (cumulative).
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Snapshot of route suitability after discovery (spec 7 "route suitability").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suitability {
    pub has_internet_route: bool,
    pub is_default_route: bool,
    pub plugged_in: bool,
}

/// Enumerates physical interfaces on the host.
pub trait InterfaceScanner {
    fn list(&self) -> Result<Vec<Interface>>;
}

/// No-op scanner for scaffolding: always returns an empty list.
pub struct NullScanner;

impl InterfaceScanner for NullScanner {
    fn list(&self) -> Result<Vec<Interface>> {
        Ok(Vec::new())
    }
}

/// Assigns a `PathId` to each discovered interface for use by the scheduler.
///
/// `PathId` is stable for the lifetime of a protection session; ids may be
/// reused across sessions.
pub struct PathMap {
    by_interface: std::collections::HashMap<String, PathId>,
    next: u8,
}

impl Default for PathMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PathMap {
    pub fn new() -> Self {
        Self {
            by_interface: std::collections::HashMap::new(),
            next: 0,
        }
    }

    /// Returns the existing path id for an interface or assigns the next free one.
    pub fn id_for(&mut self, iface: &Interface) -> PathId {
        *self.by_interface.entry(iface.id.clone()).or_insert_with(|| {
            let id = PathId::new(self.next);
            self.next = self.next.checked_add(1).unwrap_or(u8::MAX - 1);
            id
        })
    }
}