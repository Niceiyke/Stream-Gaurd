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
//!
//! V2 driver native contract (REBUILD WP-300): the blocking [`driver`] worker
//! needs verified timed/cancellable reads.
//!
//! tun-rs 2.8.9 provides them behind the `interruptible` feature as
//! `SyncDevice::recv_intr_timeout` (`poll()` + event pipe on Linux,
//! `WaitForMultipleObjects` + event on Windows, returning
//! `TimedOut`/`Interrupted`). `sg-tun` enables that feature whenever
//! `native-tun` is compiled, and [`spawn_native_driver`] binds a real adapter
//! to a [`driver::DriverTun`] on Windows/Linux only.
//!
//! All other configurations return an explicit unavailable error. No
//! production claim: native use still requires elevated privileges plus the
//! WP-901 hardware acceptance evidence (real routes, two NICs, soak); until
//! then it is an explicitly gated development path, not a supported
//! production backend.

use bytes::Bytes;
use sg_core::error::{Error, Result};

/// V2 blocking TUN driver: exclusive std-thread owner, bounded ingress and
/// per-class egress queues, durable terminal failure (REBUILD WP-300).
pub mod driver;

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

impl TunConfig {
    /// Validates adapter identity and MTU without touching the OS. The MTU is
    /// a `u32` in code but tun-rs programs it as a `u16` on the wire, so
    /// values above `u16::MAX` are rejected here instead of truncating via
    /// `as u16` (e.g. 65_536 would otherwise wrap to 0). Both the native
    /// `PlatformTun::create` and tests use this gate.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::platform("TUN adapter name must not be empty"));
        }
        if self.prefix_len > 32 {
            return Err(Error::platform("TUN prefix_len must be 0..=32"));
        }
        if self.mtu == 0 || self.mtu > u32::from(u16::MAX) {
            return Err(Error::platform("TUN mtu must be 1..=65535"));
        }
        Ok(())
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
///
/// V2 driver contract: on Windows/Linux this type also implements
/// [`driver::TunInterrupt`] via the verified `interruptible` timed read, so
/// [`spawn_native_driver`] can hand it to the blocking [`driver::DriverTun`]
/// worker. No production claim until WP-901 hardware evidence exists.
#[cfg(feature = "native-tun")]
mod platform {
    use super::*;
    use crate::driver::{InterruptTrigger, TunInterrupt};

    /// Shareable shutdown wakeup bound to the native interrupt event. Firing it
    /// makes a parked `recv_intr_timeout` return `Interrupted` promptly; the
    /// driver maps that to a clean wakeup, never a terminal fault.
    struct NativeInterrupt(std::sync::Arc<tun_rs::InterruptEvent>);

    impl InterruptTrigger for NativeInterrupt {
        fn trigger(&self) {
            // Best-effort: shutdown itself is the signal; a trigger error
            // still leaves the `poll_interval` timeout as the backstop.
            let _ = self.0.trigger();
        }
    }

    pub struct PlatformTun {
        device: tun_rs::SyncDevice,
        event: std::sync::Arc<tun_rs::InterruptEvent>,
        name: String,
        mtu: u32,
    }

    impl PlatformTun {
        pub fn create(cfg: &TunConfig) -> Result<Self> {
            cfg.validate()?;
            let mtu = u16::try_from(cfg.mtu)
                .map_err(|_| Error::platform("TUN mtu must be 1..=65535"))?;
            let mut builder = tun_rs::DeviceBuilder::new();
            builder = builder.name(cfg.name.clone());
            builder = builder.ipv4(cfg.address.as_str(), cfg.prefix_len, None);
            builder = builder.mtu(mtu);
            #[cfg(target_os = "windows")]
            {
                builder = builder.ring_capacity(0x20_0000);
                builder = builder.wintun_file(
                    std::env::var("WINTUN_DLL").unwrap_or_else(|_| "wintun.dll".into()),
                );
            }
            let device = builder.build_sync().map_err(|e| Error::io(e.to_string()))?;
            // Unix interruptible reads assume nonblocking mode per the
            // tun-rs `read_timeout` example; without it a concurrent wakeup
            // may not interrupt a blocking `recv`.
            #[cfg(unix)]
            device.set_nonblocking(true).map_err(Error::from)?;
            let event = std::sync::Arc::new(tun_rs::InterruptEvent::new().map_err(Error::from)?);
            Ok(Self {
                device,
                event,
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

    /// V2 blocking-driver backend (WP-300): timed/cancellable read bound.
    ///
    /// Verified tun-rs 2.8.9 `interruptible` semantics: `recv_intr_timeout`
    /// waits on the device plus the interrupt event up to `timeout`,
    /// returning `TimedOut` on expiry and `Interrupted` when the event fires.
    /// The driver maps both to a clean wakeup (never a terminal fault) and
    /// fires the event on every shutdown path, so `close` joins promptly
    /// without waiting out `poll_interval`. `write` persists the whole packet;
    /// short/zero counts are terminal per the driver.
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    impl TunInterrupt for PlatformTun {
        fn read_interruptible(&mut self, buf: &mut [u8], timeout: std::time::Duration) -> std::io::Result<usize> {
            self.device.recv_intr_timeout(buf, &self.event, Some(timeout))
        }

        fn write(&mut self, packet: &[u8]) -> std::io::Result<usize> {
            self.device.send(packet)
        }

        fn mtu(&self) -> u32 {
            self.mtu
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn interrupt_trigger(&self) -> Option<std::sync::Arc<dyn InterruptTrigger>> {
            Some(std::sync::Arc::new(NativeInterrupt(std::sync::Arc::clone(&self.event))))
        }
    }
}

/// Spawns a V2 [`driver::DriverTun`] owning a real platform adapter.
///
/// Available only as `Windows/Linux + native-tun`. The adapter is created
/// from `cfg` (validated interface name/CIDR/MTU), bound to the driver's
/// exclusive blocking thread, and read through the verified
/// `recv_intr_timeout` bound (`poll_interval`). No production claim: callers
/// need elevated privileges and the WP-901 hardware acceptance run; until
/// then this is a gated development path. V2 engines must `close`/`close_async`
/// the returned owner and treat any terminal failure as fatal.
#[cfg(all(feature = "native-tun", any(target_os = "windows", target_os = "linux")))]
pub fn spawn_native_driver(cfg: &TunConfig, driver_cfg: driver::DriverConfig) -> std::result::Result<driver::DriverTun, driver::DriverError> {
    let backend = platform::PlatformTun::create(cfg).map_err(|error| {
        driver::DriverError::InvalidConfig(format!("native TUN adapter unavailable: {error}"))
    })?;
    driver::DriverTun::spawn(backend, driver_cfg)
}

/// Explicitly unavailable native V2 driver construction.
///
/// Returned when the host is not `Windows/Linux + native-tun`: tun-rs timed/
/// cancellable I/O is not verified there, so WP-300's shutdown-join bound
/// cannot be met. There is intentionally no fallback that blocks forever and
/// no production claim on this path.
#[cfg(not(all(feature = "native-tun", any(target_os = "windows", target_os = "linux"))))]
pub fn spawn_native_driver(cfg: &TunConfig, driver_cfg: driver::DriverConfig) -> std::result::Result<driver::DriverTun, driver::DriverError> {
    let _ = (cfg, driver_cfg);
    Err(driver::DriverError::InvalidConfig(
        "native V2 TUN driver unavailable: requires Windows/Linux with the sg-tun `native-tun` feature (verified tun-rs interruptible timed reads); no production claim on other builds".into(),
    ))
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

    #[test]
    fn tun_config_validation_rejects_bad_identity_and_mtu() {
        // Baseline default is valid.
        TunConfig::default().validate().unwrap();

        // Empty name and bad prefix are rejected at the parsing boundary.
        let mut bad = TunConfig::default();
        bad.name.clear();
        assert!(bad.validate().is_err());
        let bad = TunConfig { prefix_len: 33, ..TunConfig::default() };
        assert!(bad.validate().is_err());

        // Zero MTU is rejected.
        let bad = TunConfig { mtu: 0, ..TunConfig::default() };
        assert!(bad.validate().is_err());

        // MTU above `u16::MAX` is rejected instead of truncating via `as u16`
        // (65_536 would otherwise wrap to 0 in the tun-rs builder).
        let bad = TunConfig { mtu: u32::from(u16::MAX) + 1, ..TunConfig::default() };
        assert!(bad.validate().is_err());
        let bad = TunConfig { mtu: u32::MAX, ..TunConfig::default() };
        assert!(bad.validate().is_err());

        // Upper bound itself remains valid.
        let ok = TunConfig { mtu: u32::from(u16::MAX), ..TunConfig::default() };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn native_driver_construction_reports_availability_explicitly() {
        // WP-300 native path is Windows/Linux + `native-tun` only, with no
        // production claim until WP-901 hardware evidence. Other builds must
        // fail with an explicit unavailable contract, never a forever-block.
        #[cfg(not(all(feature = "native-tun", any(target_os = "windows", target_os = "linux"))))]
        {
            let error = match spawn_native_driver(&TunConfig::default(), driver::DriverConfig::default()) {
                Ok(_) => panic!("native driver must be explicitly unavailable here"),
                Err(error) => error,
            };
            assert!(matches!(error, driver::DriverError::InvalidConfig(_)));
        }
        #[cfg(all(feature = "native-tun", any(target_os = "windows", target_os = "linux")))]
        {
            // Real adapter needs privileges; only assert the constructor is
            // wired (success or explicit unavailable), never a panic.
            let _ = spawn_native_driver(&TunConfig::default(), driver::DriverConfig::default());
        }
    }
}