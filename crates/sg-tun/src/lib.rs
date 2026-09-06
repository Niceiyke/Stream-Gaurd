//! Cross-platform virtual NIC (TUN) abstraction.
//!
//! Platform backends (spec section `sg-tun`):
//! - Windows: Wintun
//! - Linux: `/dev/net/tun`
//! - macOS: utun
//! - iOS: NetworkExtension `packet_tunnel_provider`
//! - Android: `VpnService`
//!
//! The scheduler reads one IP packet per `read()` and writes one IP packet
//! per `write()`; the opaque `Tun` hides the platform adapter.

use bytes::Bytes;
use sg_core::error::{Error, Result};

/// A running virtual NIC.
pub trait Tun {
    /// Non-blocking read of the next IP packet written into the TUN by the OS.
    ///
    /// Returns `WouldBlock` (as `Error::Io` with `ErrorKind::WouldBlock`)
    /// when no packet is ready.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Writes an IP packet into the TUN so the OS delivers it to the
    /// protected application.
    fn write(&mut self, packet: &[u8]) -> Result<usize>;

    /// Name of the adapter (Windows interface name / Linux iface).
    fn name(&self) -> &str;

    /// MTU currently configured on this adapter.
    fn mtu(&self) -> u32;
}

/// Builder for creating platform TUN adapters.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Adapter/interface name.
    pub name: String,
    /// IPv4 address assigned to the TUN.
    pub address: String,
    /// IPv4 netmask prefix length.
    pub prefix_len: u8,
    /// MTU to advertise inside the tunnel (spec 26.5: 1300 initial).
    pub mtu: u32,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: String::from("streamguard"),
            address: String::from("10.0.85.1"),
            prefix_len: 24,
            mtu: 1300,
        }
    }
}

/// Convenience type for an in-memory TUN used in tests.
/// Not a real adapter; use only for unit tests of the data path.
pub struct LoopbackTun {
    cfg: TunConfig,
    inbound: Vec<Bytes>,
    outbound: Vec<Bytes>,
}

impl LoopbackTun {
    pub fn with_config(cfg: TunConfig) -> Self {
        Self {
            cfg,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }

    /// Queues a packet as if the OS wrote it into the TUN.
    pub fn enqueue(&mut self, packet: Bytes) {
        self.inbound.push(packet);
    }

    /// Returns packets the scheduler wrote into the TUN.
    pub fn drain_outbound(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.outbound)
    }
}

impl Tun for LoopbackTun {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let Some(pkt) = self.inbound.first() else {
            return Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            )));
        };
        if buf.len() < pkt.len() {
            return Err(Error::platform("read buffer too small"));
        }
        let pkt = self.inbound.remove(0);
        buf[..pkt.len()].copy_from_slice(&pkt);
        Ok(pkt.len())
    }

    fn write(&mut self, packet: &[u8]) -> Result<usize> {
        self.outbound.push(Bytes::copy_from_slice(packet));
        Ok(packet.len())
    }

    fn name(&self) -> &str {
        &self.cfg.name
    }

    fn mtu(&self) -> u32 {
        self.cfg.mtu
    }
}