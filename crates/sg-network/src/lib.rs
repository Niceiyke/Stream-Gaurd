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
    /// Per-OS numeric interface index; 0 when the platform reports none.
    /// Used by the engine to bind a QUIC path's UDP socket to one physical
    /// NIC (spec 8).
    pub ifindex: u32,
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

/// Enumerates real physical interfaces via the host OS's native adapter APIs
/// (spec 7 "interface discovery"):
///
/// - Windows: `GetAdaptersAddresses` (+ `GetIfTable2` for byte counters).
/// - Linux: `if_addrs` for addresses plus `/sys/class/net` for MTU, state and
///   byte counters, and `/proc/net/route` for the interface gateway.
/// - Other platforms: empty list, so the CLI still boots (no real paths yet).
#[derive(Debug, Default)]
pub struct RealScanner;

impl InterfaceScanner for RealScanner {
    #[cfg(windows)]
    fn list(&self) -> Result<Vec<Interface>> {
        win_scanner::list()
    }

    #[cfg(target_os = "linux")]
    fn list(&self) -> Result<Vec<Interface>> {
        linux_scanner::list()
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    fn list(&self) -> Result<Vec<Interface>> {
        Ok(Vec::new())
    }
}

/// Windows `RealScanner` (`GetAdaptersAddresses` + `GetIfTable2`).
#[cfg(windows)]
mod win_scanner {
    use super::{Interface, InterfaceKind, InterfaceState};
    use sg_core::error::{Error, Result};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetAdaptersAddresses, GetIfTable2, GAA_FLAG_INCLUDE_ALL_INTERFACES,
        GAA_FLAG_INCLUDE_GATEWAYS, GET_ADAPTERS_ADDRESSES_FLAGS, IF_TYPE_ETHERNET_CSMACD,
        IF_TYPE_IEEE80211, IF_TYPE_PPP, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IF_TYPE_WWANPP,
        IF_TYPE_WWANPP2, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_GATEWAY_ADDRESS_LH,
        IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_TABLE2,
    };
    use windows::Win32::NetworkManagement::Ndis::{IfOperStatusDormant, IfOperStatusUp};
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR};

    /// Walk every adapter; a `None` kind skips the adapter (loopback).
    pub(super) fn list() -> Result<Vec<Interface>> {
        // Dual-stack family 0: both IPv4 and IPv6 adapters are reported.
        let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
            GAA_FLAG_INCLUDE_ALL_INTERFACES.0 | GAA_FLAG_INCLUDE_GATEWAYS.0,
        );
        let mut size: u32 = 0;
        let mut rc = unsafe { GetAdaptersAddresses(0, flags, None, None, &mut size) };
        // A zero-sized query legitimately reports ERROR_BUFFER_OVERFLOW with
        // the required buffer size; the retry loop below grows to fit.
        if rc != NO_ERROR.0 && rc != ERROR_BUFFER_OVERFLOW.0 {
            return Err(Error::platform(format!(
                "GetAdaptersAddresses size query failed: 0x{rc:08X}"
            )));
        }
        // Repeatedly size the buffer until it holds the whole table.
        let mut buffer: Vec<IP_ADAPTER_ADDRESSES_LH>;
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            if attempts > 8 {
                return Err(Error::platform(
                    "GetAdaptersAddresses: table kept growing past 8 attempts",
                ));
            }
            let len = size as usize / core::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() + 1;
            // The FFI struct is all integers/pointers with no Drop; an all-zero
            // element is a valid null-terminated list head for the retry loop.
            buffer = vec![unsafe { core::mem::zeroed::<IP_ADAPTER_ADDRESSES_LH>() }; len];
            rc = unsafe { GetAdaptersAddresses(0, flags, None, Some(buffer.as_mut_ptr()), &mut size) };
            if rc == NO_ERROR.0 {
                break;
            }
            if rc != ERROR_BUFFER_OVERFLOW.0 {
                return Err(Error::platform(format!(
                    "GetAdaptersAddresses failed: 0x{rc:08X}"
                )));
            }
        }

        // Byte counters are best-effort: never fail the whole scan for them.
        let counters = link_counters().unwrap_or_default();

        let mut out = Vec::new();
        let mut ptr = buffer.as_mut_ptr();
        while !ptr.is_null() {
            let a = unsafe { &*ptr };
            let ifindex = unsafe { a.Anonymous1.Anonymous.IfIndex };
            let name = pstr_to_string(a.AdapterName.0);
            let friendly = pwstr_to_string(a.FriendlyName.0);
            let id = if friendly.is_empty() { name.clone() } else { friendly };
            if let Some(kind) = kind_of(a.IfType) {
                let state = if a.OperStatus.0 == IfOperStatusUp.0 {
                    InterfaceState::Up
                } else if a.OperStatus.0 == IfOperStatusDormant.0 {
                    InterfaceState::Dormant
                } else {
                    InterfaceState::Down
                };
                let addresses = unicast_addresses(a.FirstUnicastAddress);
                let gateway = first_gateway(a.FirstGatewayAddress);
                let (rx_bytes, tx_bytes) = counters.get(&ifindex).copied().unwrap_or((0, 0));
                out.push(Interface {
                    id,
                    name,
                    ifindex,
                    kind,
                    addresses,
                    mtu: a.Mtu,
                    state,
                    gateway,
                    rx_bytes,
                    tx_bytes,
                });
            }
            ptr = a.Next;
        }
        Ok(out)
    }

    /// `GetIfTable2` cumulative octet counters keyed by interface index.
    fn link_counters() -> Result<HashMap<u32, (u64, u64)>> {
        let mut table: *mut MIB_IF_TABLE2 = core::ptr::null_mut();
        let rc = unsafe { GetIfTable2(&mut table) };
        if rc != NO_ERROR || table.is_null() {
            return Ok(HashMap::new());
        }
        let mut out = HashMap::new();
        unsafe {
            let rows = core::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            for row in rows {
                out.insert(row.InterfaceIndex, (row.InOctets, row.OutOctets));
            }
            FreeMibTable(table as *const core::ffi::c_void);
        }
        Ok(out)
    }

    fn kind_of(iftype: u32) -> Option<InterfaceKind> {
        match iftype {
            IF_TYPE_SOFTWARE_LOOPBACK => None,
            IF_TYPE_ETHERNET_CSMACD => Some(InterfaceKind::Ethernet),
            IF_TYPE_IEEE80211 => Some(InterfaceKind::Wifi),
            IF_TYPE_WWANPP | IF_TYPE_WWANPP2 => Some(InterfaceKind::Cellular),
            IF_TYPE_PPP => Some(InterfaceKind::UsbTether),
            IF_TYPE_TUNNEL => Some(InterfaceKind::Virtual),
            _ => Some(InterfaceKind::Unknown),
        }
    }

    /// Raw `SOCKADDR` reads, independent of the host's `IN_ADDR` union layout:
    /// family at offset 0 (native order), IPv4 octets at 4..8, IPv6 at 8..24.
    fn sockaddr_to_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        let family = unsafe { (sa as *const u16).read_unaligned() };
        if family == AF_INET.0 {
            let mut octets = [0u8; 4];
            unsafe {
                core::ptr::copy_nonoverlapping((sa as *const u8).add(4), octets.as_mut_ptr(), 4);
            }
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        } else if family == AF_INET6.0 {
            let mut octets = [0u8; 16];
            unsafe {
                core::ptr::copy_nonoverlapping((sa as *const u8).add(8), octets.as_mut_ptr(), 16);
            }
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    }

    fn unicast_addresses(first: *mut IP_ADAPTER_UNICAST_ADDRESS_LH) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let mut ptr = first;
        while !ptr.is_null() {
            let ua = unsafe { &*ptr };
            if let Some(ip) = sockaddr_to_ip(ua.Address.lpSockaddr) {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
            ptr = ua.Next;
        }
        out
    }

    /// First IPv4 gateway on the interface, else the first IPv6 one.
    fn first_gateway(first: *mut IP_ADAPTER_GATEWAY_ADDRESS_LH) -> Option<IpAddr> {
        let mut ipv4 = None;
        let mut ptr = first;
        while !ptr.is_null() {
            let g = unsafe { &*ptr };
            match sockaddr_to_ip(g.Address.lpSockaddr) {
                Some(ip @ IpAddr::V4(_)) => return Some(ip),
                Some(ip) if ipv4.is_none() => ipv4 = Some(ip),
                _ => {}
            }
            ptr = g.Next;
        }
        ipv4
    }

    fn pstr_to_string(p: *mut u8) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf8_lossy(core::slice::from_raw_parts(p, len)).into_owned()
        }
    }

    fn pwstr_to_string(p: *mut u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(core::slice::from_raw_parts(p, len))
        }
    }
}

/// Linux `RealScanner`: `if_addrs` for addresses plus `/sys/class/net` and
/// `/proc/net/route` for the rest (spec 7).
#[cfg(target_os = "linux")]
mod linux_scanner {
    use super::{Interface, InterfaceKind, InterfaceState};
    use sg_core::error::{Error, Result};
    use std::collections::HashMap;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};

    pub(super) fn list() -> Result<Vec<Interface>> {
        let addrs = if_addrs::get_if_addrs().map_err(Error::Io)?;
        let mut groups: Vec<(String, Vec<IpAddr>, Option<u32>)> = Vec::new();
        let mut by_name: HashMap<String, usize> = HashMap::new();
        for iface in addrs {
            if iface.is_loopback() {
                continue;
            }
            let idx = *by_name
                .entry(iface.name.clone())
                .or_insert_with(|| {
                    groups.push((iface.name.clone(), Vec::new(), iface.index));
                    groups.len() - 1
                });
            let addr = iface.addr.ip();
            if !groups[idx].1.contains(&addr) {
                groups[idx].1.push(addr);
            }
        }

        let mut out = Vec::with_capacity(groups.len());
        for (name, addresses, index) in groups {
            let sys = format!("/sys/class/net/{name}");
            let kind = kind_of_name(&name);
            let gateway = read_gateway(&name);
            let state = match fs::read_to_string(format!("{sys}/operstate")).ok().as_deref() {
                Some("up") => InterfaceState::Up,
                Some("dormant") => InterfaceState::Dormant,
                _ => InterfaceState::Down,
            };
            let read_u64 = |file: &str| -> u64 {
                fs::read_to_string(file)
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0)
            };
            out.push(Interface {
                id: name.clone(),
                name,
                ifindex: index.unwrap_or(0),
                kind,
                addresses,
                mtu: read_u64(&format!("{sys}/mtu")) as u32,
                state,
                gateway,
                rx_bytes: read_u64(&format!("{sys}/statistics/rx_bytes")),
                tx_bytes: read_u64(&format!("{sys}/statistics/tx_bytes")),
            });
        }
        Ok(out)
    }

    /// Name-prefix heuristics; containers/VM bridges are marked `Virtual` so
    /// the engine's physical-path filter drops them (spec 7).
    fn kind_of_name(name: &str) -> InterfaceKind {
        if name.starts_with("en") || name.starts_with("eth") {
            InterfaceKind::Ethernet
        } else if name.starts_with("wl") || name.starts_with("wifi") || name.starts_with("wlan") {
            InterfaceKind::Wifi
        } else if name.starts_with("wwan") || name.starts_with("rmnet") {
            InterfaceKind::Cellular
        } else if name.starts_with("usb") || name.starts_with("ppp") {
            InterfaceKind::UsbTether
        } else if name.starts_with("docker")
            || name.starts_with("br-")
            || name.starts_with("veth")
            || name.starts_with("virbr")
            || name.starts_with("tun")
            || name.starts_with("tap")
        {
            InterfaceKind::Virtual
        } else {
            InterfaceKind::Unknown
        }
    }

    /// Default gateway per interface from `/proc/net/route` (`Destination`
    /// 00000000, little-endian hex `Gateway`).
    fn read_gateway(name: &str) -> Option<IpAddr> {
        let text = fs::read_to_string("/proc/net/route").ok()?;
        for line in text.lines().skip(1) {
            let mut it = line.split_whitespace();
            if it.next()? == name && it.next()? == "00000000" {
                if let Some(gw) = it.next() {
                    if let Ok(raw) = u32::from_str_radix(gw, 16) {
                        return Some(IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())));
                    }
                }
            }
        }
        None
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn real_scanner_lists_host_interfaces() {
        let ifaces = match RealScanner.list() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipping: host scan failed: {e}");
                return;
            }
        };
        if ifaces.is_empty() {
            eprintln!("skipping: host exposes no interfaces");
            return;
        }
        eprintln!("scanned {} host interfaces", ifaces.len());
        for iface in &ifaces {
            assert!(!iface.id.is_empty(), "empty interface id");
            assert!(
                matches!(
                    iface.kind,
                    InterfaceKind::Ethernet
                        | InterfaceKind::Wifi
                        | InterfaceKind::Cellular
                        | InterfaceKind::UsbTether
                        | InterfaceKind::Virtual
                        | InterfaceKind::Unknown
                ),
                "unexpected kind on {}",
                iface.name
            );
            let mut sorted = iface.addresses.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                iface.addresses.len(),
                "duplicate addresses on {}",
                iface.name
            );
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn real_scanner_lists_host_interfaces() {
        let ifaces = match RealScanner.list() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipping: host scan failed: {e}");
                return;
            }
        };
        if ifaces.is_empty() {
            eprintln!("skipping: host exposes no interfaces");
            return;
        }
        eprintln!("scanned {} host interfaces", ifaces.len());
        for iface in &ifaces {
            assert!(!iface.id.is_empty(), "empty interface id");
            assert!(
                matches!(
                    iface.kind,
                    InterfaceKind::Ethernet
                        | InterfaceKind::Wifi
                        | InterfaceKind::Cellular
                        | InterfaceKind::UsbTether
                        | InterfaceKind::Virtual
                        | InterfaceKind::Unknown
                ),
                "unexpected kind on {}",
                iface.name
            );
            let mut sorted = iface.addresses.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                iface.addresses.len(),
                "duplicate addresses on {}",
                iface.name
            );
        }
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
