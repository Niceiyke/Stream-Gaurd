//! Cross-platform virtual NIC (TUN) abstraction.
//!
//! Platform backends (spec section `sg-tun`):
//! - Windows: Wintun
//! - Linux: `/dev/net/tun`
//! - macOS: utun
//! - iOS: NetworkExtension `packet_tunnel_provider`
//! - Android: `VpnService`
//!
//! The engine reads one IP packet per `read()` and writes one IP packet
//! per `write()`; the opaque `Tun` hides the platform adapter. The real
//! tun-rs (v2) backend is compiled only with the `native-tun` feature:
//! it is off by default so the scaffold builds and tests on any host
//! without drivers (see the gateway and Windows milestones).

use bytes::Bytes;
use sg_core::error::{Error, Result};

/// A running virtual NIC.
pub trait Tun {
    /// Reads the next IP packet written into the TUN by the OS.
    ///
    /// Blocking on real platform adapters; callers must drive those on a
    /// dedicated task (spec 22.5). The in-memory `LoopbackTun` instead
    /// returns `WouldBlock` once its queue is drained.
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
    ///
    /// On macOS this must be `utunX`; on Windows the adapter is a Wintun
    /// session and the name is informational.
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

/// Renders a dotted netmask from a prefix length (e.g. 24 -> 255.255.255.0).
pub fn netmask_str(prefix_len: u8) -> String {
    let bits = prefix_len.min(32);
    let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff
    )
}

/// Opens a TUN adapter for the current platform (spec engineering steps
/// 2 and 3). Without the `native-tun` feature this returns
/// `Error::Platform` so tests and the dev `LoopbackTun` fallback can run
/// on any host.
pub fn create(cfg: &TunConfig) -> Result<Box<dyn Tun>> {
    #[cfg(feature = "native-tun")]
    {
        Ok(Box::new(platform::PlatformTun::create(cfg)?))
    }
    #[cfg(not(feature = "native-tun"))]
    {
        let _ = cfg;
        Err(Error::platform(
            "native TUN backend not compiled; enable the sg-tun `native-tun` feature",
        ))
    }
}

/// Real tun-rs (v2) adapter: Wintun on Windows, /dev/net/tun on Linux,
/// utun on macOS. Loads `wintun.dll` at runtime on Windows (configurable
/// via `WINTUN_DLL`), so it compiles without embedding any DLL.
#[cfg(feature = "native-tun")]
mod platform {
    use super::*;

    pub struct PlatformTun {
        device: tun_rs::SyncDevice,
        name: String,
        mtu: u32,
    }

    impl PlatformTun {
        pub fn create(cfg: &TunConfig) -> Result<Self> {
            let mut builder = tun_rs::DeviceBuilder::new();
            builder = builder.name(cfg.name.clone());
            builder = builder.ipv4(cfg.address.as_str(), cfg.prefix_len, None);
            builder = builder.mtu(cfg.mtu as u16);
            #[cfg(target_os = "windows")]
            {
                builder = builder.ring_capacity(0x20_0000);
                builder = builder.wintun_file(
                    std::env::var("WINTUN_DLL").unwrap_or_else(|_| "wintun.dll".into()),
                );
            }
            let device = builder.build_sync().map_err(|e| Error::io(e.to_string()))?;
            Ok(Self {
                device,
                name: cfg.name.clone(),
                mtu: cfg.mtu,
            })
        }
    }

    impl Tun for PlatformTun {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.device.recv(buf).map_err(Error::from)
        }

        fn write(&mut self, packet: &[u8]) -> Result<usize> {
            self.device.send(packet).map_err(Error::from)
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn mtu(&self) -> u32 {
            self.mtu
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_renders_dotted_quad() {
        assert_eq!(netmask_str(24), "255.255.255.0");
        assert_eq!(netmask_str(0), "0.0.0.0");
        assert_eq!(netmask_str(32), "255.255.255.255");
    }

    #[test]
    fn loopback_tun_round_trips_packets() {
        let mut tun = LoopbackTun::with_config(TunConfig::default());
        let packet = Bytes::from_static(&[0x45, 0x00, 0x00, 0x14]);
        tun.enqueue(packet.clone());
        let mut buf = [0u8; 64];
        assert_eq!(tun.read(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], &packet[..]);
        assert!(matches!(
            tun.read(&mut buf),
            Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert_eq!(tun.write(&packet).unwrap(), 4);
        assert_eq!(tun.drain_outbound(), vec![packet]);
    }

    #[test]
    fn create_without_native_feature_is_unavailable() {
        #[cfg(not(feature = "native-tun"))]
        assert!(create(&TunConfig::default()).is_err());
        #[cfg(feature = "native-tun")]
        let _ = create(&TunConfig::default()); // real adapter: requires privileges
    }
}